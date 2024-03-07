from random import randint
from typing import Tuple, List
import secrets
import sys
import asyncio

from secp256k1ref.secp256k1 import GE, G
from secp256k1ref.keys import pubkey_gen_plain
from reference import (
    secret_share_shard,
    kdf,
    vss_verify,
    vss_commit,
    vss_sum_commitments,
    simplpedpop_round1,
    simplpedpop_pre_finalize,
    encpedpop_round1,
    encpedpop_pre_finalize,
    chilldkg_hostkey_gen,
    chilldkg_session_params,
    chilldkg_round1,
    chilldkg_round2,
    chilldkg_finalize,
    chilldkg_recover,
    CoordinatorChannels,
    SignerChannel,
    chilldkg,
    chilldkg_coordinate,
    polynomial_evaluate,
)


def scalar_add_multi(scalars: List[int]) -> int:
    acc = 0
    for scalar in scalars:
        acc = (acc + scalar) % GE.ORDER
    return acc


def test_vss_correctness():
    def rand_polynomial(t):
        return [randint(1, GE.ORDER - 1) for _ in range(1, t + 1)]

    for t in range(1, 3):
        for n in range(t, 2 * t + 1):
            f = rand_polynomial(t)
            shares = secret_share_shard(f, n)
            assert len(shares) == n
            assert all(vss_verify(i, shares[i], vss_commit(f)) for i in range(n))


def simulate_simplpedpop(seeds, t):
    n = len(seeds)
    round1_outputs = []
    dkg_outputs = []
    for i in range(n):
        round1_outputs += [simplpedpop_round1(seeds[i], t, n, i)]
    vss_commitments_ext = [out[1] for out in round1_outputs]
    vss_commitments_sum = vss_sum_commitments(vss_commitments_ext, t)
    for i in range(n):
        shares_sum = scalar_add_multi([out[2][i] for out in round1_outputs])
        dkg_outputs += [
            simplpedpop_pre_finalize(
                round1_outputs[i][0], vss_commitments_sum, shares_sum
            )
        ]
    return dkg_outputs


def encpedpop_keys(seed: bytes) -> Tuple[bytes, bytes]:
    my_deckey = kdf(seed, "deckey")
    my_enckey = pubkey_gen_plain(my_deckey)
    return my_deckey, my_enckey


def simulate_encpedpop(seeds, t):
    n = len(seeds)
    round0_outputs = []
    round1_outputs = []
    dkg_outputs = []
    for i in range(n):
        round0_outputs += [encpedpop_keys(seeds[i])]

    enckeys = [out[1] for out in round0_outputs]
    for i in range(n):
        my_deckey = round0_outputs[i][0]
        round1_outputs += [encpedpop_round1(seeds[i], t, n, my_deckey, enckeys, i)]

    vss_commitments_ext = [out[1] for out in round1_outputs]
    vss_commitments_sum = vss_sum_commitments(vss_commitments_ext, t)
    for i in range(n):
        enc_shares_sum = scalar_add_multi([out[2][i] for out in round1_outputs])
        dkg_outputs += [
            encpedpop_pre_finalize(
                round1_outputs[i][0], vss_commitments_sum, enc_shares_sum
            )
        ]
    return dkg_outputs


def simulate_chilldkg(seeds, t):
    n = len(seeds)

    hostkeys = []
    for i in range(n):
        hostkeys += [chilldkg_hostkey_gen(seeds[i])]

    hostpubkeys = [hostkey[1] for hostkey in hostkeys]
    params, _ = chilldkg_session_params(hostpubkeys, t, b"")

    round1_outputs = []
    for i in range(n):
        round1_outputs += [chilldkg_round1(seeds[i], params)]

    state1s = [out[0] for out in round1_outputs]
    vss_commitments_ext = [out[1] for out in round1_outputs]
    vss_commitments_sum = vss_sum_commitments(vss_commitments_ext, t)
    dkg_outputs = []
    all_enc_shares_sum = []
    for i in range(n):
        all_enc_shares_sum += [scalar_add_multi([out[2][i] for out in round1_outputs])]
    round2_outputs = []
    for i in range(n):
        round2_outputs += [
            chilldkg_round2(
                seeds[i], state1s[i], vss_commitments_sum, all_enc_shares_sum
            )
        ]

    cert = b"".join([out[1] for out in round2_outputs])
    for i in range(n):
        dkg_outputs += [chilldkg_finalize(round2_outputs[i][0], cert)]

    return dkg_outputs


def simulate_chilldkg_full(seeds, t):
    n = len(seeds)
    hostkeys = []
    for i in range(n):
        hostkeys += [chilldkg_hostkey_gen(seeds[i])]

    params = chilldkg_session_params([hostkey[1] for hostkey in hostkeys], t, b"")[0]

    async def main():
        coord_chans = CoordinatorChannels(n)
        signer_chans = [SignerChannel(coord_chans.queues[i]) for i in range(n)]
        coord_chans.set_signer_queues([signer_chans[i].queue for i in range(n)])
        coroutines = [chilldkg_coordinate(coord_chans, params)] + [
            chilldkg(signer_chans[i], seeds[i], hostkeys[i][0], params)
            for i in range(n)
        ]
        return await asyncio.gather(*coroutines)

    outputs = asyncio.run(main())
    # Check coordinator output
    assert outputs[0][0] == outputs[1][0][1]
    assert outputs[0][1] == outputs[1][0][2]
    return [[out[0][0], out[0][1], out[0][2], out[1]] for out in outputs[1:]]


# Adapted from BIP 324
def scalar_inv(a: int):
    """Compute the modular inverse of a modulo n using the extended Euclidean
    Algorithm. See https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers.
    """
    a = a % GE.ORDER
    if a == 0:
        return 0
    if sys.hexversion >= 0x3080000:
        # More efficient version available in Python 3.8.
        return pow(a, -1, GE.ORDER)
    t1, t2 = 0, 1
    r1, r2 = GE.ORDER, a
    while r2 != 0:
        q = r1 // r2
        t1, t2 = t2, t1 - q * t2
        r1, r2 = r2, r1 - q * r2
    if r1 > 1:
        return None
    if t1 < 0:
        t1 += GE.ORDER
    return t1


def derive_interpolating_value(L, x_i):
    assert x_i in L
    assert all(L.count(x_j) <= 1 for x_j in L)
    numerator = 1
    denominator = 1
    for x_j in L:
        if x_j == x_i:
            continue
        numerator = (numerator * x_j) % GE.ORDER
        denominator = (denominator * ((x_j - x_i) % GE.ORDER)) % GE.ORDER
    denom_inv = scalar_inv(denominator)
    return (numerator * denom_inv) % GE.ORDER


def recover_secret(signer_indices, shares):
    interpolated_shares = []
    t = len(shares)
    assert len(signer_indices) == t
    for i in range(t):
        lam = derive_interpolating_value(signer_indices, signer_indices[i])
        interpolated_shares += [(lam * shares[i]) % GE.ORDER]
    recovered_secret = scalar_add_multi(interpolated_shares)
    return recovered_secret


def test_recover_secret():
    f = [23, 42]
    shares = [polynomial_evaluate(f, i) for i in [1, 2, 3]]
    assert recover_secret([1, 2], [shares[0], shares[1]]) == f[0]
    assert recover_secret([1, 3], [shares[0], shares[2]]) == f[0]
    assert recover_secret([2, 3], [shares[1], shares[2]]) == f[0]


def dkg_correctness(t, n, simulate_dkg, external_eq):
    seeds = [secrets.token_bytes(32) for _ in range(n)]

    dkg_outputs = simulate_dkg(seeds, t)
    assert all([out is not False for out in dkg_outputs])
    if external_eq:
        # TODO: move into separate function "eta_eq"
        etas = [out[0] for out in dkg_outputs]
        assert len(etas) == n
        for i in range(1, n):
            assert etas[0] == etas[i]
        dkg_outputs = [out[1] for out in dkg_outputs]

    shares = [out[0] for out in dkg_outputs]
    shared_pubkeys = [out[1] for out in dkg_outputs]
    signer_pubkeys = [out[2] for out in dkg_outputs]

    # Check that the shared pubkey and signer_pubkeys are the same for all
    # participants
    assert len(set(shared_pubkeys)) == 1
    shared_pubkey = shared_pubkeys[0]
    for i in range(1, n):
        assert signer_pubkeys[0] == signer_pubkeys[i]

    # Check that the share corresponds to the signer_pubkey
    for i in range(n):
        assert shares[i] * G == signer_pubkeys[0][i]

    # Check that the first t signers (TODO: should be an arbitrary set) can
    # recover the shared pubkey
    recovered_secret = recover_secret(list(range(1, t + 1)), shares[0:t])
    assert recovered_secret * G == shared_pubkey

    # test correctness of chilldkg_recover
    if len(dkg_outputs[0]) > 3:
        for i in range(n):
            (share, shared_pubkey_, signer_pubkeys_), _ = chilldkg_recover(
                seeds[i], dkg_outputs[i][3], b""
            )
            assert share == shares[i]
            assert shared_pubkey_ == shared_pubkeys[i]
            assert signer_pubkeys_ == signer_pubkeys[i]


test_vss_correctness()
test_recover_secret()
for t, n in [(1, 1), (1, 2), (2, 2), (2, 3), (2, 5)]:
    external_eq = True
    dkg_correctness(t, n, simulate_simplpedpop, external_eq)
    dkg_correctness(t, n, simulate_encpedpop, external_eq)
    external_eq = False
    dkg_correctness(t, n, simulate_chilldkg, external_eq)
    dkg_correctness(t, n, simulate_chilldkg_full, external_eq)
