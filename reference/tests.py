from random import randint
from typing import Tuple
import secrets
import asyncio

from secp256k1ref.secp256k1 import GE, G, Scalar
from secp256k1ref.keys import pubkey_gen_plain

from util import kdf
from vss import Polynomial, VSS
import simplpedpop
import encpedpop
from chilldkg import (
    CoordinatorChannels,
    SignerChannel,
    hostkey_gen,
    session_params,
    signer_step1,
    signer_step2,
    signer_finalize,
    signer_recover,
    coordinator_step,
    signer,
    coordinator,
)


def test_vss_correctness():
    def rand_polynomial(t):
        return Polynomial([randint(1, GE.ORDER - 1) for _ in range(1, t + 1)])

    for t in range(1, 3):
        for n in range(t, 2 * t + 1):
            f = rand_polynomial(t)
            vss = VSS(f)
            shares = vss.shares(n)
            assert len(shares) == n
            assert all(vss.commit().verify(i, shares[i]) for i in range(n))


def simulate_simplpedpop(seeds, t):
    n = len(seeds)
    soutputs = []
    dkg_outputs = []
    for i in range(n):
        soutputs += [simplpedpop.signer_step(seeds[i], t, n, i)]
    smsgs = [out[1] for out in soutputs]
    cmsg = simplpedpop.coordinator_step(smsgs, t)
    for i in range(n):
        shares_sum = Scalar.sum(*([out[2][i] for out in soutputs]))
        dkg_outputs += [
            simplpedpop.signer_pre_finalize(soutputs[i][0], cmsg, shares_sum)
        ]
    return dkg_outputs


def encpedpop_keys(seed: bytes) -> Tuple[bytes, bytes]:
    deckey = kdf(seed, "deckey")
    enckey = pubkey_gen_plain(deckey)
    return deckey, enckey


def simulate_encpedpop(seeds, t):
    n = len(seeds)
    enc_soutputs0 = []
    enc_soutputs1 = []
    dkg_outputs = []
    for i in range(n):
        enc_soutputs0 += [encpedpop_keys(seeds[i])]

    enckeys = [out[1] for out in enc_soutputs0]
    for i in range(n):
        deckey = enc_soutputs0[i][0]
        enc_soutputs1 += [encpedpop.signer_step(seeds[i], t, n, deckey, enckeys, i)]

    smsgs = [smsg for (_, smsg) in enc_soutputs1]
    sstates = [sstate for (sstate, _) in enc_soutputs1]
    cmsg, enc_shares_sums = encpedpop.coordinator_step(smsgs, t)
    for i in range(n):
        dkg_outputs += [
            encpedpop.signer_pre_finalize(sstates[i], cmsg, enc_shares_sums[i])
        ]
    return dkg_outputs


def simulate_chilldkg(seeds, t):
    n = len(seeds)

    hostkeys = []
    for i in range(n):
        hostkeys += [hostkey_gen(seeds[i])]

    hostpubkeys = [hostkey[1] for hostkey in hostkeys]
    params, _ = session_params(hostpubkeys, t, b"")

    chill_soutputs1 = []
    for i in range(n):
        chill_soutputs1 += [signer_step1(seeds[i], params)]

    chill_sstate1s = [out[0] for out in chill_soutputs1]
    chill_smsgs = [out[1] for out in chill_soutputs1]
    chill_cmsg = coordinator_step(chill_smsgs, t)

    chill_soutputs2 = []
    for i in range(n):
        chill_soutputs2 += [signer_step2(seeds[i], chill_sstate1s[i], chill_cmsg)]

    cert = b"".join([out[1] for out in chill_soutputs2])

    dkg_outputs = []
    for i in range(n):
        dkg_outputs += [signer_finalize(chill_soutputs2[i][0], cert)]

    return dkg_outputs


def simulate_chilldkg_full(seeds, t):
    n = len(seeds)
    hostkeys = []
    for i in range(n):
        hostkeys += [hostkey_gen(seeds[i])]

    params = session_params([hostkey[1] for hostkey in hostkeys], t, b"")[0]

    async def main():
        coord_chans = CoordinatorChannels(n)
        signer_chans = [SignerChannel(coord_chans.queues[i]) for i in range(n)]
        coord_chans.set_signer_queues([signer_chans[i].queue for i in range(n)])
        coroutines = [coordinator(coord_chans, params)] + [
            signer(signer_chans[i], seeds[i], hostkeys[i][0], params) for i in range(n)
        ]
        return await asyncio.gather(*coroutines)

    outputs = asyncio.run(main())
    # Check coordinator output
    assert outputs[0][0] == outputs[1][0][1]
    assert outputs[0][1] == outputs[1][0][2]
    return [[out[0][0], out[0][1], out[0][2], out[1]] for out in outputs[1:]]


def derive_interpolating_value(L, x_i):
    assert x_i in L
    assert all(L.count(x_j) <= 1 for x_j in L)
    lam = Scalar(1)
    for x_j in L:
        x_j = Scalar(x_j)
        x_i = Scalar(x_i)
        if x_j == x_i:
            continue
        lam *= x_j / (x_j - x_i)
    return lam


def recover_secret(signer_indices, shares) -> Scalar:
    interpolated_shares = []
    t = len(shares)
    assert len(signer_indices) == t
    for i in range(t):
        lam = derive_interpolating_value(signer_indices, signer_indices[i])
        interpolated_shares += [(lam * shares[i])]
    recovered_secret = Scalar.sum(*interpolated_shares)
    return recovered_secret


def test_recover_secret():
    f = Polynomial([23, 42])
    shares = [f(i) for i in [1, 2, 3]]
    assert recover_secret([1, 2], [shares[0], shares[1]]) == f.coeffs[0]
    assert recover_secret([1, 3], [shares[0], shares[2]]) == f.coeffs[0]
    assert recover_secret([2, 3], [shares[1], shares[2]]) == f.coeffs[0]


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
            (share, shared_pubkey_, signer_pubkeys_), _ = signer_recover(
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
