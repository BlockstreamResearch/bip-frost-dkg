#!/usr/bin/env python3

"""Tests for ChillDKG reference implementation"""

from itertools import combinations
from random import randint
from typing import Tuple, List
import secrets

from secp256k1ref.secp256k1 import GE, G, Scalar
from secp256k1ref.keys import pubkey_gen_plain

from chilldkg_ref.util import prf
from chilldkg_ref.vss import Polynomial, VSS
import chilldkg_ref.simplpedpop as simplpedpop
import chilldkg_ref.encpedpop as encpedpop
import chilldkg_ref.chilldkg as chilldkg

from example import simulate_chilldkg_full


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
    prets = []
    for i in range(n):
        prets += [simplpedpop.participant_step1(seeds[i], t, n, i)]
    pmsgs = [ret[1] for ret in prets]

    cmsg, cout, ceq = simplpedpop.coordinator_step(pmsgs, t, n)
    pre_finalize_rets = [(cout, ceq)]
    for i in range(n):
        shares_sum = Scalar.sum(*([pret[2][i] for pret in prets]))
        pre_finalize_rets += [
            simplpedpop.participant_step2(prets[i][0], cmsg, shares_sum)
        ]
    return pre_finalize_rets


def encpedpop_keys(seed: bytes) -> Tuple[bytes, bytes]:
    deckey = prf(seed, "encpedpop deckey")
    enckey = pubkey_gen_plain(deckey)
    return deckey, enckey


def simulate_encpedpop(seeds, t) -> List[Tuple[simplpedpop.DKGOutput, bytes]]:
    n = len(seeds)
    enc_prets0 = []
    enc_prets1 = []
    for i in range(n):
        enc_prets0 += [encpedpop_keys(seeds[i])]

    enckeys = [pret[1] for pret in enc_prets0]
    for i in range(n):
        deckey = enc_prets0[i][0]
        enc_prets1 += [encpedpop.participant_step1(seeds[i], t, deckey, enckeys, i)]

    pmsgs = [pmsg for (_, pmsg) in enc_prets1]
    pstates = [pstate for (pstate, _) in enc_prets1]

    cmsg, cout, ceq, enc_shares_sums = encpedpop.coordinator_step(pmsgs, t, enckeys)
    pre_finalize_rets = [(cout, ceq)]
    for i in range(n):
        pre_finalize_rets += [
            encpedpop.participant_step2(pstates[i], cmsg, enc_shares_sums[i])
        ]
    return pre_finalize_rets


def simulate_chilldkg(
    seeds, t
) -> List[Tuple[simplpedpop.DKGOutput, chilldkg.RecoveryData]]:
    n = len(seeds)

    hostkeys = []
    for i in range(n):
        hostkeys += [chilldkg.hostkey_gen(seeds[i])]

    hostpubkeys = [hostkey[1] for hostkey in hostkeys]
    params, _ = chilldkg.session_params(hostpubkeys, t)

    prets1 = []
    for i in range(n):
        prets1 += [chilldkg.participant_step1(seeds[i], params)]

    pstates1 = [pret[0] for pret in prets1]
    pmsgs = [pret[1] for pret in prets1]
    cstate, cmsg = chilldkg.coordinator_step(pmsgs, params)

    prets2 = []
    for i in range(n):
        prets2 += [chilldkg.participant_step2(seeds[i], pstates1[i], cmsg)]

    cmsg2, cout, crec = chilldkg.coordinator_finalize(
        cstate, [pret[1] for pret in prets2]
    )
    outputs = [(cout, crec)]
    for i in range(n):
        out = chilldkg.participant_finalize(prets2[i][0], cmsg2)
        assert out is not None
        outputs += [out]

    return outputs


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


def recover_secret(participant_indices, shares) -> Scalar:
    interpolated_shares = []
    t = len(shares)
    assert len(participant_indices) == t
    for i in range(t):
        lam = derive_interpolating_value(participant_indices, participant_indices[i])
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
    pubshares = [out[2] for out in dkg_outputs]

    # Check that the threshold pubkey and pubshares are the same for the
    # coordinator (at [0]) and all participants (at [1:n + 1]).
    for i in range(n + 1):
        assert threshold_pubkeys[0] == threshold_pubkeys[i]
        assert len(pubshares[i]) == n
        assert pubshares[0] == pubshares[i]
    threshold_pubkey = threshold_pubkeys[0]

    # Check that the coordinator has no secret share
    assert secshares[0] is None

    # Check that each secshare matches the corresponding pubshare
    for i in range(1, n + 1):
        assert secshares[i] * G == pubshares[0][i - 1]

    # Check that all combinations of t participants can recover the threshold pubkey
    for tsubset in combinations(range(1, n + 1), t):
        recovered_secret = recover_secret(tsubset, [secshares[i] for i in tsubset])
        assert recovered_secret * G == threshold_pubkey


def test_correctness(t, n, simulate_dkg, recovery=False):
    seeds = [None] + [secrets.token_bytes(32) for _ in range(n)]

    # rets[0] are the return values from the coordinator
    # rets[1 : n + 1] are from the participants
    rets = simulate_dkg(seeds[1:], t)
    assert len(rets) == n + 1

    dkg_outputs = [ret[0] for ret in rets]
    test_correctness_dkg_output(t, n, dkg_outputs)

    eqs_or_recs = [ret[1] for ret in rets]
    for i in range(1, n + 1):
        assert eqs_or_recs[0] == eqs_or_recs[i]

    if recovery:
        rec = eqs_or_recs[0]
        # Check correctness of chilldkg.recover
        for i in range(n + 1):
            (secshare, threshold_pubkey, pubshares), _ = chilldkg.recover(seeds[i], rec)
            assert secshare == dkg_outputs[i][0]
            assert threshold_pubkey == dkg_outputs[i][1]
            assert pubshares == dkg_outputs[i][2]


test_vss_correctness()
test_recover_secret()
for t, n in [(1, 1), (1, 2), (2, 2), (2, 3), (2, 5)]:
    test_correctness(t, n, simulate_simplpedpop)
    test_correctness(t, n, simulate_encpedpop)
    test_correctness(t, n, simulate_chilldkg, recovery=True)
    test_correctness(t, n, simulate_chilldkg_full, recovery=True)
