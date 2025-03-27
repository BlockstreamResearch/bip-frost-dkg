#!/usr/bin/env python3

"""Tests for ChillDKG reference implementation"""

from itertools import combinations
from random import randint
from typing import Tuple, List, Optional
from secrets import token_bytes as random_bytes

from secp256k1lab.secp256k1 import GE, G, Scalar
from secp256k1lab.keys import pubkey_gen_plain

from chilldkg_ref.util import (
    FaultyParticipantOrCoordinatorError,
    FaultyCoordinatorError,
    UnknownFaultyParticipantOrCoordinatorError,
    tagged_hash_bip_dkg,
)
from chilldkg_ref.vss import Polynomial, VSS, VSSCommitment
import chilldkg_ref.simplpedpop as simplpedpop
import chilldkg_ref.encpedpop as encpedpop
import chilldkg_ref.chilldkg as chilldkg

from example import simulate_chilldkg_full as simulate_chilldkg_full_example


def test_chilldkg_params_validate():
    hostseckeys = [random_bytes(32) for _ in range(3)]
    hostpubkeys = [chilldkg.hostpubkey_gen(hostseckey) for hostseckey in hostseckeys]

    with_duplicate = [hostpubkeys[0], hostpubkeys[1], hostpubkeys[2], hostpubkeys[1]]
    params_with_duplicate = chilldkg.SessionParams(with_duplicate, 2)
    try:
        _ = chilldkg.params_id(params_with_duplicate)
    except chilldkg.DuplicateHostPubkeyError as e:
        assert {e.participant1, e.participant2} == {1, 3}
    else:
        assert False, "Expected exception"

    invalid_hostpubkey = b"\x03" + 31 * b"\x00" + b"\x05"  # Invalid x-coordinate
    params_with_invalid = chilldkg.SessionParams(
        [hostpubkeys[1], invalid_hostpubkey, hostpubkeys[2]], 1
    )
    try:
        _ = chilldkg.params_id(params_with_invalid)
    except chilldkg.InvalidHostPubkeyError as e:
        assert e.participant == 1
        pass
    else:
        assert False, "Expected exception"

    try:
        _ = chilldkg.params_id(
            chilldkg.SessionParams(hostpubkeys, len(hostpubkeys) + 1)
        )
    except chilldkg.ThresholdOrCountError:
        pass
    else:
        assert False, "Expected exception"

    try:
        _ = chilldkg.params_id(chilldkg.SessionParams(hostpubkeys, -2))
    except chilldkg.ThresholdOrCountError:
        pass
    else:
        assert False, "Expected exception"


def test_vss_correctness():
    def rand_polynomial(t):
        return Polynomial([randint(1, GE.ORDER - 1) for _ in range(1, t + 1)])

    for t in range(1, 3):
        for n in range(t, 2 * t + 1):
            f = rand_polynomial(t)
            vss = VSS(f)
            secshares = vss.secshares(n)
            assert len(secshares) == n
            assert all(
                VSSCommitment.verify_secshare(secshares[i], vss.commit().pubshare(i))
                for i in range(n)
            )

            vssc_tweaked, tweak, pubtweak = vss.commit().invalid_taproot_commit()
            assert VSSCommitment.verify_secshare(
                vss.secret() + tweak, vss.commit().commitment_to_secret() + pubtweak
            )
            assert all(
                VSSCommitment.verify_secshare(
                    secshares[i] + tweak, vssc_tweaked.pubshare(i)
                )
                for i in range(n)
            )


def simulate_simplpedpop(
    seeds, t, investigation: bool
) -> Optional[List[Tuple[simplpedpop.DKGOutput, bytes]]]:
    n = len(seeds)
    prets = []
    for i in range(n):
        prets += [simplpedpop.participant_step1(seeds[i], t, n, i)]

    pstates = [pstate for (pstate, _, _) in prets]
    pmsgs = [pmsg for (_, pmsg, _) in prets]

    cmsg, cout, ceq = simplpedpop.coordinator_step(pmsgs, t, n)
    pre_finalize_rets = [(cout, ceq)]
    for i in range(n):
        partial_secshares = [
            partial_secshares_for[i] for (_, _, partial_secshares_for) in prets
        ]
        if investigation:
            # Let a random participant send incorrect shares to participant i.
            faulty_idx = randint(0, n - 1)
            partial_secshares[faulty_idx] += Scalar(17)

        secshare = simplpedpop.participant_step2_prepare_secshare(partial_secshares)
        try:
            pre_finalize_rets += [
                simplpedpop.participant_step2(pstates[i], cmsg, secshare)
            ]
        except UnknownFaultyParticipantOrCoordinatorError as e:
            if not investigation:
                raise
            inv_msgs = simplpedpop.coordinator_investigate(pmsgs)
            assert len(inv_msgs) == len(pmsgs)
            try:
                simplpedpop.participant_investigate(e, inv_msgs[i], partial_secshares)
            # If we're not faulty, we should blame the faulty party.
            except FaultyParticipantOrCoordinatorError as e:
                assert i != faulty_idx
                assert e.participant == faulty_idx
            # If we're faulty, we'll blame the coordinator.
            except FaultyCoordinatorError:
                assert i == faulty_idx
            return None
    return pre_finalize_rets


def encpedpop_keys(seed: bytes) -> Tuple[bytes, bytes]:
    deckey = tagged_hash_bip_dkg("encpedpop deckey", seed)
    enckey = pubkey_gen_plain(deckey)
    return deckey, enckey


def simulate_encpedpop(
    seeds, t, investigation: bool
) -> Optional[List[Tuple[simplpedpop.DKGOutput, bytes]]]:
    n = len(seeds)
    enc_prets0 = []
    enc_prets1 = []
    for i in range(n):
        enc_prets0 += [encpedpop_keys(seeds[i])]

    enckeys = [pret[1] for pret in enc_prets0]
    for i in range(n):
        deckey = enc_prets0[i][0]
        random = random_bytes(32)
        enc_prets1 += [
            encpedpop.participant_step1(seeds[i], deckey, enckeys, t, i, random)
        ]

    pstates = [pstate for (pstate, _) in enc_prets1]
    pmsgs = [pmsg for (_, pmsg) in enc_prets1]
    if investigation:
        faulty_idx: List[int] = []
        for i in range(n):
            # Let a random participant faulty_idx[i] send incorrect shares to i.
            faulty_idx[i:] = [randint(0, n - 1)]
            faulty_pmsg = encpedpop.ParticipantMsg.from_bytes_and_n(
                pmsgs[faulty_idx[i]], n
            )
            faulty_pmsg.enc_shares[i] += Scalar(17)
            pmsgs[faulty_idx[i]] = faulty_pmsg.to_bytes()

    cmsg, cout, ceq, enc_secshares = encpedpop.coordinator_step(pmsgs, t, enckeys)
    pre_finalize_rets = [(cout, ceq)]
    for i in range(n):
        deckey = enc_prets0[i][0]
        try:
            pre_finalize_rets += [
                encpedpop.participant_step2(pstates[i], deckey, cmsg, enc_secshares[i])
            ]
        except UnknownFaultyParticipantOrCoordinatorError as e:
            if not investigation:
                raise
            inv_msgs = encpedpop.coordinator_investigate(pmsgs)
            assert len(inv_msgs) == len(pmsgs)
            try:
                encpedpop.participant_investigate(e, inv_msgs[i])
            # If we're not faulty, we should blame the faulty party.
            except FaultyParticipantOrCoordinatorError as e:
                assert i != faulty_idx[i]
                assert e.participant == faulty_idx[i]
            # If we're faulty, we'll blame the coordinator.
            except FaultyCoordinatorError:
                assert i == faulty_idx[i]
            return None
    return pre_finalize_rets


def simulate_chilldkg(
    hostseckeys, t, investigation: bool
) -> Optional[List[Tuple[chilldkg.DKGOutput, chilldkg.RecoveryData]]]:
    n = len(hostseckeys)

    hostpubkeys = []
    for i in range(n):
        hostpubkeys += [chilldkg.hostpubkey_gen(hostseckeys[i])]

    params = chilldkg.SessionParams(hostpubkeys, t)

    prets1 = []
    for i in range(n):
        random = random_bytes(32)
        prets1 += [chilldkg.participant_step1(hostseckeys[i], params, random)]

    pstates1 = [pret[0] for pret in prets1]
    pmsgs = [pret[1] for pret in prets1]
    if investigation:
        faulty_idx: List[int] = []
        for i in range(n):
            # Let a random participant faulty_idx[i] send incorrect shares to i.
            faulty_idx[i:] = [randint(0, n - 1)]
            faulty_pmsg = chilldkg.ParticipantMsg1.from_bytes_and_n(
                pmsgs[faulty_idx[i]], n
            )
            faulty_pmsg.enc_pmsg.enc_shares[i] += Scalar(17)
            pmsgs[faulty_idx[i]] = faulty_pmsg.to_bytes()

    cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs, params)

    prets2 = []
    for i in range(n):
        try:
            prets2 += [chilldkg.participant_step2(hostseckeys[i], pstates1[i], cmsg1)]
        except UnknownFaultyParticipantOrCoordinatorError as e:
            if not investigation:
                raise
            inv_msgs = chilldkg.coordinator_investigate(pmsgs)
            assert len(inv_msgs) == len(pmsgs)
            try:
                chilldkg.participant_investigate(e, inv_msgs[i])
            # If we're not faulty, we should blame the faulty party.
            except FaultyParticipantOrCoordinatorError as e:
                assert i != faulty_idx[i]
                assert e.participant == faulty_idx[i]
            # If we're faulty, we'll blame the coordinator.
            except FaultyCoordinatorError:
                assert i == faulty_idx[i]
            return None

    cmsg2, cout, crec = chilldkg.coordinator_finalize(
        cstate, [pret[1] for pret in prets2]
    )
    outputs = [(cout, crec)]
    for i in range(n):
        out = chilldkg.participant_finalize(prets2[i][0], cmsg2)
        assert out is not None
        outputs += [out]

    return outputs


def simulate_chilldkg_full(
    hostseckeys,
    t,
    investigation: bool,
) -> List[Optional[Tuple[chilldkg.DKGOutput, chilldkg.RecoveryData]]]:
    # Investigating is not supported by this wrapper
    assert not investigation

    hostpubkeys = []
    for i in range(n):
        hostpubkeys += [chilldkg.hostpubkey_gen(hostseckeys[i])]
    params = chilldkg.SessionParams(hostpubkeys, t)
    return simulate_chilldkg_full_example(hostseckeys, params, faulty_idx=None)


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
    secshares_scalar = [
        None if secshare is None else Scalar.from_bytes(secshare)
        for secshare in secshares
    ]
    for i in range(1, n + 1):
        assert secshares_scalar[i] * G == GE.from_bytes_compressed(pubshares[0][i - 1])

    # Check that all combinations of t participants can recover the threshold pubkey
    for tsubset in combinations(range(1, n + 1), t):
        recovered = recover_secret(tsubset, [secshares_scalar[i] for i in tsubset])
        assert recovered * G == GE.from_bytes_compressed(threshold_pubkey)


def test_correctness(t, n, simulate_dkg, recovery=False, investigation=False):
    seeds = [None] + [random_bytes(32) for _ in range(n)]

    rets = simulate_dkg(seeds[1:], t, investigation=investigation)
    if investigation:
        assert rets is None
        # The session has failed correctly, so there's nothing further to check.
        return

    # rets[0] are the return values from the coordinator
    # rets[1 : n + 1] are from the participants
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


test_chilldkg_params_validate()
test_vss_correctness()
test_recover_secret()
for t, n in [(1, 1), (1, 2), (2, 2), (2, 3), (2, 5)]:
    test_correctness(t, n, simulate_simplpedpop)
    test_correctness(t, n, simulate_simplpedpop, investigation=True)
    test_correctness(t, n, simulate_encpedpop)
    test_correctness(t, n, simulate_encpedpop, investigation=True)
    test_correctness(t, n, simulate_chilldkg, recovery=True)
    test_correctness(t, n, simulate_chilldkg, recovery=True, investigation=True)
    test_correctness(t, n, simulate_chilldkg_full, recovery=True)
