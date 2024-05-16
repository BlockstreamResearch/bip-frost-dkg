from itertools import combinations
from random import randint
from typing import Tuple, List
import secrets
import asyncio

from secp256k1ref.secp256k1 import GE, G, Scalar
from secp256k1ref.keys import pubkey_gen_plain

from util import kdf
from vss import Polynomial, VSS
import simplpedpop
import encpedpop
import chilldkg
from chilldkg import CoordinatorChannels, SignerChannel


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


def simulate_simplpedpop(seeds, t) -> List[Tuple[simplpedpop.DKGOutput, bytes]]:
    n = len(seeds)
    srets = []
    for i in range(n):
        srets += [simplpedpop.signer_step(seeds[i], t, n, i)]
    smsgs = [ret[1] for ret in srets]

    cmsg, cout, ceta = simplpedpop.coordinator_step(smsgs, t, n)
    pre_finalize_outputs = [(cout, ceta)]
    for i in range(n):
        shares_sum = Scalar.sum(*([sret[2][i] for sret in srets]))
        pre_finalize_outputs += [
            simplpedpop.signer_pre_finalize(srets[i][0], cmsg, shares_sum)
        ]
    return pre_finalize_outputs


def encpedpop_keys(seed: bytes) -> Tuple[bytes, bytes]:
    deckey = kdf(seed, "deckey")
    enckey = pubkey_gen_plain(deckey)
    return deckey, enckey


def simulate_encpedpop(seeds, t) -> List[Tuple[simplpedpop.DKGOutput, bytes]]:
    n = len(seeds)
    enc_srets0 = []
    enc_srets1 = []
    for i in range(n):
        enc_srets0 += [encpedpop_keys(seeds[i])]

    enckeys = [sret[1] for sret in enc_srets0]
    for i in range(n):
        deckey = enc_srets0[i][0]
        enc_srets1 += [encpedpop.signer_step(seeds[i], t, deckey, enckeys, i)]

    smsgs = [smsg for (_, smsg) in enc_srets1]
    sstates = [sstate for (sstate, _) in enc_srets1]

    cmsg, cout, ceta, enc_shares_sums = encpedpop.coordinator_step(smsgs, t, enckeys)
    pre_finalize_outputs = [(cout, ceta)]
    for i in range(n):
        pre_finalize_outputs += [
            encpedpop.signer_pre_finalize(sstates[i], cmsg, enc_shares_sums[i])
        ]
    return pre_finalize_outputs


def simulate_chilldkg(
    seeds, t
) -> List[Tuple[simplpedpop.DKGOutput, chilldkg.RecoveryData]]:
    n = len(seeds)

    hostkeys = []
    for i in range(n):
        hostkeys += [chilldkg.hostkey_gen(seeds[i])]

    hostpubkeys = [hostkey[1] for hostkey in hostkeys]
    params, _ = chilldkg.session_params(hostpubkeys, t, b"")

    srets1 = []
    for i in range(n):
        srets1 += [chilldkg.signer_step1(seeds[i], params)]

    sstate1s = [sret[0] for sret in srets1]
    smsgs = [sret[1] for sret in srets1]
    cstate, cmsg = chilldkg.coordinator_step(smsgs, params)

    srets2 = []
    for i in range(n):
        srets2 += [chilldkg.signer_step2(seeds[i], sstate1s[i], cmsg)]

    cmsg2, cout, crec = chilldkg.coordinator_finalize(
        cstate, [sret[1] for sret in srets2]
    )
    outputs = [(cout, crec)]
    for i in range(n):
        out = chilldkg.signer_finalize(srets2[i][0], cmsg2)
        assert out is not None
        outputs += [out]

    return outputs


def simulate_chilldkg_full(
    seeds, t
) -> List[Tuple[simplpedpop.DKGOutput, chilldkg.RecoveryData]]:
    n = len(seeds)
    hostkeys = []
    for i in range(n):
        hostkeys += [chilldkg.hostkey_gen(seeds[i])]

    params = chilldkg.session_params([hostkey[1] for hostkey in hostkeys], t, b"")[0]

    async def main():
        coord_chans = CoordinatorChannels(n)
        signer_chans = [SignerChannel(coord_chans.queues[i]) for i in range(n)]
        coord_chans.set_signer_queues([signer_chans[i].queue for i in range(n)])
        coroutines = [chilldkg.coordinator(coord_chans, params)] + [
            chilldkg.signer(signer_chans[i], seeds[i], hostkeys[i][0], params)
            for i in range(n)
        ]
        return await asyncio.gather(*coroutines)

    outputs = asyncio.run(main())

    # Check coordinator output
    return [
        (
            simplpedpop.DKGOutput(out[0][0], out[0][1], out[0][2]),
            chilldkg.RecoveryData(out[1]),
        )
        for out in outputs
    ]


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


def test_correctness_dkg_output(t, n, dkg_outputs: List[simplpedpop.DKGOutput]):
    assert len(dkg_outputs) == n + 1
    secshares = [out[0] for out in dkg_outputs]
    threshold_pubkeys = [out[1] for out in dkg_outputs]
    signer_pubshares = [out[2] for out in dkg_outputs]

    # Check that the threshold pubkey and signer_pubshares are the same for the
    # coordinator (at [0]) and all participants (at [1:n + 1]).
    for i in range(n + 1):
        assert threshold_pubkeys[0] == threshold_pubkeys[i]
        assert len(signer_pubshares[i]) == n
        assert signer_pubshares[0] == signer_pubshares[i]
    threshold_pubkey = threshold_pubkeys[0]

    # Check that the coordinator has no secret share
    assert secshares[0] is None

    # Check that each secshare matches the corresponding signer_pubshare
    # (secshares[1:])
    for i in range(1, n + 1):
        assert secshares[i] * G == signer_pubshares[0][i - 1]

    # Check that all combinations of t signers can recover the threshold pubkey
    for tsubset in combinations(range(1, n + 1), t):
        recovered_secret = recover_secret(tsubset, [secshares[i] for i in tsubset])
        assert recovered_secret * G == threshold_pubkey


def test_correctness(t, n, simulate_dkg, recovery=False):
    seeds = [secrets.token_bytes(32) for _ in range(n)]

    # rets[0] are the return values from the coordinator
    # rets[1 : n + 1] are from the participants
    rets = simulate_dkg(seeds, t)
    assert len(rets) == n + 1

    dkg_outputs = [ret[0] for ret in rets]
    test_correctness_dkg_output(t, n, dkg_outputs)

    etas_or_recs = [ret[1] for ret in rets]
    for i in range(1, n + 1):
        assert etas_or_recs[0] == etas_or_recs[i]

    if recovery:
        rec = etas_or_recs[0]
        # test correctness of chilldkg_recover
        for i in range(1, n + 1):
            (secshare, threshold_pubkey, signer_pubshares), _ = chilldkg.signer_recover(
                seeds[i - 1], rec, b""
            )
            assert secshare == dkg_outputs[i][0]
            assert threshold_pubkey == dkg_outputs[i][1]
            assert signer_pubshares == dkg_outputs[i][2]


test_vss_correctness()
test_recover_secret()
for t, n in [(1, 1), (1, 2), (2, 2), (2, 3), (2, 5)]:
    test_correctness(t, n, simulate_simplpedpop)
    test_correctness(t, n, simulate_encpedpop)
    test_correctness(t, n, simulate_chilldkg, recovery=True)
    test_correctness(t, n, simulate_chilldkg_full, recovery=True)
