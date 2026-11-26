#!/usr/bin/env python3

"""Tests for ChillDKG reference implementation"""

import json
from pathlib import Path
from random import randint
from secrets import token_bytes as random_bytes

from chilldkg_ref import chilldkg, encpedpop, simplpedpop
from chilldkg_ref.util import (
    FaultyCoordinatorError,
    FaultyParticipantError,
    FaultyParticipantOrCoordinatorError,
    UnknownFaultyParticipantOrCoordinatorError,
    tagged_hash_bip_dkg,
)
from chilldkg_ref.vss import VSS, Polynomial, VSSCommitment
from example import simulate_chilldkg_full as simulate_chilldkg_full_example
from gen_vector_utils.util import (
    assert_raises,
    expect_exception,
    expect_faulty_exception,
    params_asdict,
    params_from_dict,
    threshold_info_asdict,
)

# Import secp256k1lab and modules that use it (bip445_threshold_info) after the
# chilldkg_ref imports because the latter modifies sys.path to make sure the
# vendored copy of secp256k1lab is found.
#
# isort: split
from secp256k1lab.keys import pubkey_gen_plain
from secp256k1lab.secp256k1 import GE, G, Scalar

import bip445_threshold_info as bip445
from bip445_threshold_info import MAX_PARTICIPANTS


def test_chilldkg_params_validate():
    hostseckeys = [random_bytes(32) for _ in range(3)]
    hostpubkeys = [chilldkg.hostpubkey_gen(hostseckey) for hostseckey in hostseckeys]

    with_duplicate = [hostpubkeys[0], hostpubkeys[1], hostpubkeys[2], hostpubkeys[1]]
    params_with_duplicate = chilldkg.SessionParams(with_duplicate, 2)
    try:
        _ = chilldkg.params_hash(params_with_duplicate)
    except chilldkg.DuplicateHostPubkeyError as e:
        assert {e.participant_id1, e.participant_id2} == {1, 3}
    else:
        assert False, "Expected exception"

    invalid_hostpubkey = b"\x03" + 31 * b"\x00" + b"\x05"  # Invalid x-coordinate
    params_with_invalid = chilldkg.SessionParams(
        [hostpubkeys[1], invalid_hostpubkey, hostpubkeys[2]], 1
    )
    try:
        _ = chilldkg.params_hash(params_with_invalid)
    except chilldkg.InvalidHostPubkeyError as e:
        assert e.participant_id == 1
    else:
        assert False, "Expected exception"

    try:
        _ = chilldkg.params_hash(
            chilldkg.SessionParams(hostpubkeys, len(hostpubkeys) + 1)
        )
    except chilldkg.ThresholdOrCountError:
        pass
    else:
        assert False, "Expected exception"

    try:
        _ = chilldkg.params_hash(chilldkg.SessionParams(hostpubkeys, -2))
    except chilldkg.ThresholdOrCountError:
        pass
    else:
        assert False, "Expected exception"

    max_n = chilldkg.MAX_PARTICIPANTS
    many_hostpubkeys = [
        chilldkg.hostpubkey_gen(random_bytes(32)) for _ in range(max_n + 1)
    ]
    _ = chilldkg.params_hash(chilldkg.SessionParams(many_hostpubkeys[:max_n], 2))
    try:
        _ = chilldkg.params_hash(chilldkg.SessionParams(many_hostpubkeys, 2))
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
) -> list[tuple[bytes | None, simplpedpop.ThresholdInfo, bytes]] | None:
    n = len(seeds)
    prets = []
    for i in range(n):
        random = random_bytes(32)
        prets += [simplpedpop.participant_step1(seeds[i], t, n, i, random)]

    pstates = [pstate for (pstate, _, _) in prets]
    pmsgs = [pmsg for (_, pmsg, _) in prets]

    cmsg, csum_coms, ceq = simplpedpop.coordinator_step(pmsgs, t, n)
    cinfo, _ = simplpedpop.threshold_info_from_sum_coms(csum_coms, n)
    pre_finalize_rets: list[tuple[bytes | None, simplpedpop.ThresholdInfo, bytes]]
    pre_finalize_rets = [(None, cinfo, ceq)]
    for i in range(n):
        partial_secshares = [
            partial_secshares_for[i] for (_, _, partial_secshares_for) in prets
        ]
        if investigation:
            # Let a random participant send incorrect shares to participant i.
            faulty_id = randint(0, n - 1)
            partial_secshares[faulty_id] += Scalar(17)

        secshare = simplpedpop.participant_step2_prepare_secshare(partial_secshares)
        try:
            psecshare, psum_coms, peq = simplpedpop.participant_step2(
                pstates[i], cmsg, secshare
            )
            pinfo, _ = simplpedpop.threshold_info_from_sum_coms(psum_coms, n)
            pre_finalize_rets += [(psecshare, pinfo, peq)]
        except UnknownFaultyParticipantOrCoordinatorError as e:
            if not investigation:
                raise
            inv_msgs = simplpedpop.coordinator_investigate(pmsgs, t)
            assert len(inv_msgs) == len(pmsgs)
            try:
                simplpedpop.participant_investigate(e, inv_msgs[i], partial_secshares)
            # If we're not faulty, we should blame the faulty party.
            except FaultyParticipantOrCoordinatorError as e:
                assert i != faulty_id
                assert e.participant_id == faulty_id
            # If we're faulty, we'll blame the coordinator.
            except FaultyCoordinatorError:
                assert i == faulty_id
            return None
    return pre_finalize_rets


def encpedpop_keys(seed: bytes) -> tuple[bytes, bytes]:
    deckey = tagged_hash_bip_dkg("encpedpop deckey", seed)
    enckey = pubkey_gen_plain(deckey)
    return deckey, enckey


def simulate_encpedpop(
    seeds, t, investigation: bool
) -> list[tuple[bytes | None, simplpedpop.ThresholdInfo, bytes]] | None:
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
        faulty_id: list[int] = []
        for i in range(n):
            # Let a random participant faulty_id[i] send incorrect shares to
            # participant i.
            faulty_id[i:] = [randint(0, n - 1)]
            faulty_pmsg = encpedpop.ParticipantMsg.from_bytes(
                pmsgs[faulty_id[i]], t=t, n=n
            )
            faulty_pmsg.enc_shares[i] += Scalar(17)
            pmsgs[faulty_id[i]] = faulty_pmsg.to_bytes()

    cmsg, csum_coms, ceq, enc_secshares = encpedpop.coordinator_step(pmsgs, t, enckeys)
    cinfo, _ = simplpedpop.threshold_info_from_sum_coms(csum_coms, n)
    pre_finalize_rets: list[tuple[bytes | None, simplpedpop.ThresholdInfo, bytes]]
    pre_finalize_rets = [(None, cinfo, ceq)]
    for i in range(n):
        deckey = enc_prets0[i][0]
        try:
            psecshare, psum_coms, peq = encpedpop.participant_step2(
                pstates[i], deckey, cmsg, enc_secshares[i]
            )
            pinfo, _ = simplpedpop.threshold_info_from_sum_coms(psum_coms, n)
            pre_finalize_rets += [(psecshare, pinfo, peq)]
        except UnknownFaultyParticipantOrCoordinatorError as e:
            if not investigation:
                raise
            inv_msgs = encpedpop.coordinator_investigate(pmsgs, t)
            assert len(inv_msgs) == len(pmsgs)
            try:
                encpedpop.participant_investigate(e, inv_msgs[i])
            # If we're not faulty, we should blame the faulty party.
            except FaultyParticipantOrCoordinatorError as e:
                assert i != faulty_id[i]
                assert e.participant_id == faulty_id[i]
            # If we're faulty, we'll blame the coordinator.
            except FaultyCoordinatorError:
                assert i == faulty_id[i]
            return None
    return pre_finalize_rets


def simulate_chilldkg(
    hostseckeys, t, investigation: bool
) -> list[tuple[bytes | None, chilldkg.ThresholdInfo, chilldkg.RecoveryData]] | None:
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
        faulty_id: list[int] = []
        for i in range(n):
            # Let a random participant faulty_id[i] send incorrect shares
            # to participant i.
            faulty_id[i:] = [randint(0, n - 1)]
            faulty_pmsg = chilldkg.ParticipantMsg1.from_bytes(
                pmsgs[faulty_id[i]], t=t, n=n
            )
            faulty_pmsg.enc_pmsg.enc_shares[i] += Scalar(17)
            pmsgs[faulty_id[i]] = faulty_pmsg.to_bytes()

    cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs, params)

    prets2 = []
    for i in range(n):
        try:
            random = random_bytes(32)
            prets2 += [
                chilldkg.participant_step2(hostseckeys[i], pstates1[i], cmsg1, random)
            ]
        except UnknownFaultyParticipantOrCoordinatorError as e:
            if not investigation:
                raise
            inv_msgs = chilldkg.coordinator_investigate(pmsgs, params)
            assert len(inv_msgs) == len(pmsgs)
            try:
                chilldkg.participant_investigate(e, inv_msgs[i])
            # If we're not faulty, we should blame the faulty party.
            except FaultyParticipantOrCoordinatorError as e:
                assert i != faulty_id[i]
                assert e.participant_id == faulty_id[i]
            # If we're faulty, we'll blame the coordinator.
            except FaultyCoordinatorError:
                assert i == faulty_id[i]
            return None

    cmsg2, cinfo, crec = chilldkg.coordinator_finalize(
        cstate, [pret[1] for pret in prets2]
    )
    outputs: list[tuple[bytes | None, chilldkg.ThresholdInfo, chilldkg.RecoveryData]]
    outputs = [(None, cinfo, crec)]
    for i in range(n):
        out = chilldkg.participant_finalize(prets2[i][0], cmsg2)
        assert out is not None
        outputs += [out]

    return outputs


def simulate_chilldkg_full(
    hostseckeys,
    t,
    investigation: bool,
) -> list[tuple[bytes | None, chilldkg.ThresholdInfo, chilldkg.RecoveryData] | None]:
    # Investigating is not supported by this wrapper
    assert not investigation

    hostpubkeys = []
    for i in range(n):
        hostpubkeys += [chilldkg.hostpubkey_gen(hostseckeys[i])]
    params = chilldkg.SessionParams(hostpubkeys, t)
    return simulate_chilldkg_full_example(hostseckeys, params, faulty_id=None)


def validate_threshold_info(info: chilldkg.ThresholdInfo) -> None:
    # Convert to the types of the BIP 445 reference implementation
    bip445.validate_threshold_info(
        bip445.ThresholdInfo(
            info.t,
            bip445.PlainPk(info.thresh_pk),
            [bip445.PlainPk(pubshare) for pubshare in info.pubshares],
        )
    )


def test_validate_threshold_info():
    # Sanity check of the copied validation function.
    t, n = 2, 3
    f = Polynomial([randint(1, GE.ORDER - 1) for _ in range(t)])
    thresh_pk = (f(0) * G).to_bytes_compressed()
    pubshares = [(f(i + 1) * G).to_bytes_compressed() for i in range(n)]
    # A point on the polynomial, but at a position that belongs to no participant
    other_point = (f(n + 1) * G).to_bytes_compressed()
    # Public shares of a polynomial with constant term 0, i.e., shares whose
    # threshold public key would be the point at infinity
    f_zero = Polynomial([0] + f.coeffs[1:])
    zero_pubshares = [(f_zero(i + 1) * G).to_bytes_compressed() for i in range(n)]

    info = chilldkg.ThresholdInfo(t, thresh_pk, pubshares)
    validate_threshold_info(info)

    invalid_infos = [
        # Threshold out of range
        (info._replace(t=0), "The threshold must be 1 <= t <= n."),
        (info._replace(t=n + 1), "The threshold must be 1 <= t <= n."),
        # Threshold public key is not a valid point
        (info._replace(thresh_pk=b"\x00" * 33), "The thresh_pk is not a valid point."),
        # Threshold public key does not match the public shares
        (
            info._replace(thresh_pk=other_point),
            "The provided key material is incorrect: the public shares do not match the threshold public key.",
        ),
        # A public share is not a valid point
        (
            info._replace(pubshares=pubshares[:-1] + [b"\x00" * 33]),
            f"The pubshare at index {n - 1} is not a valid point.",
        ),
        # A public share does not lie on the polynomial through the first t
        (
            info._replace(pubshares=pubshares[:-1] + [other_point]),
            "The provided key material is incorrect: the public shares do not lie on a single polynomial.",
        ),
        # The public shares interpolate to the point at infinity
        (
            info._replace(pubshares=zero_pubshares),
            "The threshold public key must not be the point at infinity.",
        ),
        # Too many participants for BIP 445
        (
            info._replace(pubshares=[pubshares[0]] * (MAX_PARTICIPANTS + 1)),
            f"The number of participants must be n <= {MAX_PARTICIPANTS}.",
        ),
    ]
    for invalid_info, expected_msg in invalid_infos:
        try:
            validate_threshold_info(invalid_info)
        except ValueError as e:
            assert e.args == (expected_msg,)
        else:
            assert False, "Expected exception"

    # BIP 445 permits absent public shares (`None` entries), which
    # chilldkg.ThresholdInfo cannot represent, so call the copied function
    # directly.
    bip445_thresh_pk = bip445.PlainPk(thresh_pk)
    bip445_pubshares = [bip445.PlainPk(pubshare) for pubshare in pubshares]
    # At least t public shares present
    bip445.validate_threshold_info(
        bip445.ThresholdInfo(
            t, bip445_thresh_pk, [bip445_pubshares[0], None, bip445_pubshares[2]]
        )
    )
    # Fewer than t public shares present
    try:
        bip445.validate_threshold_info(
            bip445.ThresholdInfo(t, bip445_thresh_pk, [bip445_pubshares[0], None, None])
        )
    except ValueError as e:
        assert e.args == ("At least t pubshares must be present.",)
    else:
        assert False, "Expected exception"


def test_correctness_outputs(
    t,
    n,
    secshares: list[bytes | None],
    threshold_infos: list[chilldkg.ThresholdInfo],
):
    assert len(secshares) == len(threshold_infos) == n + 1

    # Check that the threshold info is the same for the coordinator (at [0]) and
    # all participants (at [1:n + 1]), and that it matches the session.
    for i in range(n + 1):
        assert threshold_infos[i] == threshold_infos[0]
    threshold_info = threshold_infos[0]
    assert threshold_info.t == t
    assert len(threshold_info.pubshares) == n
    pubshares = threshold_info.pubshares

    # Check that the coordinator has no secret share
    assert secshares[0] is None

    # Check that each secshare matches the corresponding pubshare
    secshares_scalar = [
        None if secshare is None else Scalar.from_bytes_checked(secshare)
        for secshare in secshares
    ]
    for i in range(1, n + 1):
        s = secshares_scalar[i]
        assert s is not None
        assert s * G == GE.from_bytes_compressed(pubshares[i - 1])

    # Check that the threshold info passes the validation that BIP 445 requires
    # before signing.
    validate_threshold_info(threshold_info)


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
    secshares = [ret[0] for ret in rets]
    threshold_infos = [ret[1] for ret in rets]
    test_correctness_outputs(t, n, secshares, threshold_infos)

    eqs_or_recs = [ret[2] for ret in rets]
    for i in range(1, n + 1):
        assert eqs_or_recs[0] == eqs_or_recs[i]

    if recovery:
        rec = eqs_or_recs[0]
        # Check correctness of chilldkg.participant_recover /
        # chilldkg.coordinator_recover
        for i in range(n + 1):
            if seeds[i] is None:
                threshold_info, _ = chilldkg.coordinator_recover(rec)
            else:
                secshare, threshold_info, _ = chilldkg.participant_recover(
                    seeds[i], rec
                )
                assert secshare == secshares[i]
            assert threshold_info == threshold_infos[i]


VECTORS_DIR = Path(__file__).parent.parent / "vectors"


def test_hostpubkey_gen_vectors():
    input_file = VECTORS_DIR / "hostpubkey_gen_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    valid_test_cases = test_data["validTestCases"]
    error_test_cases = (
        test_data["errorTestCases"] + test_data["inputValidationErrorTestCases"]
    )
    assert test_data["totalTests"] == len(valid_test_cases) + len(error_test_cases)

    for test_case in valid_test_cases:
        hostseckey = bytes.fromhex(test_case["hostseckey"])
        expected_hostpubkey = bytes.fromhex(test_case["expectedHostpubkey"])
        assert expected_hostpubkey == chilldkg.hostpubkey_gen(hostseckey)

    for test_case in error_test_cases:
        hostseckey = bytes.fromhex(test_case["hostseckey"])
        expected_error = test_case["expectedError"]
        assert_raises(lambda: chilldkg.hostpubkey_gen(hostseckey), expected_error)


def test_params_hash_vectors():
    input_file = VECTORS_DIR / "params_hash_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    valid_test_cases = test_data["validTestCases"]
    error_test_cases = (
        test_data["errorTestCases"] + test_data["inputValidationErrorTestCases"]
    )
    assert test_data["totalTests"] == len(valid_test_cases) + len(error_test_cases)

    for test_case in valid_test_cases:
        params = params_from_dict(test_case["params"])
        expected_hash = bytes.fromhex(test_case["expectedParamsHash"])
        assert expected_hash == chilldkg.params_hash(params)

    for test_case in error_test_cases:
        params = params_from_dict(test_case["params"])
        expected_error = test_case["expectedError"]
        assert_raises(lambda: chilldkg.params_hash(params), expected_error)


def test_participant_step1_vectors():
    input_file = VECTORS_DIR / "participant_step1_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    total_cases = 0
    for group in test_data["testGroups"]:
        for test_case in group["validTestCases"]:
            hostseckey = bytes.fromhex(test_case["hostseckey"])
            params = params_from_dict(test_case["params"])
            random = bytes.fromhex(test_case["random"])
            expected_pmsg1 = bytes.fromhex(test_case["expectedPmsg1"])
            _, pmsg1 = chilldkg.participant_step1(hostseckey, params, random)
            assert expected_pmsg1 == pmsg1
            total_cases += 1
            assert test_case["tcId"] == total_cases

        for test_case in (
            group["errorTestCases"] + group["inputValidationErrorTestCases"]
        ):
            hostseckey = bytes.fromhex(test_case["hostseckey"])
            params = params_from_dict(test_case["params"])
            random = bytes.fromhex(test_case["random"])
            expected_error = test_case["expectedError"]
            assert_raises(
                lambda: chilldkg.participant_step1(hostseckey, params, random),
                expected_error,
            )
            total_cases += 1
            assert test_case["tcId"] == total_cases

    assert test_data["totalTests"] == total_cases


def test_participant_step2_vectors():
    input_file = VECTORS_DIR / "participant_step2_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    total_cases = 0
    for group in test_data["testGroups"]:
        # common fields for all test cases
        params = params_from_dict(group["params"])
        hostseckey = bytes.fromhex(group["hostseckey"])
        random = bytes.fromhex(group["random"])

        state1, pmsg1 = chilldkg.participant_step1(hostseckey, params, random)
        assert bytes.fromhex(group["pmsg1"]) == pmsg1  # checkpoint

        for test_case in group["validTestCases"]:
            case_hostseckey = bytes.fromhex(
                test_case.get("hostseckey", group["hostseckey"])
            )
            case_random = bytes.fromhex(test_case.get("random", group["random"]))
            case_aux_rand = bytes.fromhex(test_case.get("auxRand", group["auxRand"]))
            cmsg1 = bytes.fromhex(test_case["cmsg1"])
            expected_pmsg2 = bytes.fromhex(test_case["expectedPmsg2"])
            if case_hostseckey != hostseckey or case_random != random:
                case_state1, case_pmsg1 = chilldkg.participant_step1(
                    case_hostseckey, params, case_random
                )
            else:
                case_state1 = state1
                case_pmsg1 = pmsg1
            if "pmsg1" in test_case:
                assert case_pmsg1 == bytes.fromhex(test_case["pmsg1"])
            _, pmsg2 = chilldkg.participant_step2(
                case_hostseckey, case_state1, cmsg1, case_aux_rand
            )
            assert expected_pmsg2 == pmsg2
            total_cases += 1
            assert test_case["tcId"] == total_cases

        for test_case in (
            group["errorTestCases"] + group["inputValidationErrorTestCases"]
        ):
            case_hostseckey = bytes.fromhex(
                test_case.get("hostseckey", group["hostseckey"])
            )
            case_aux_rand = bytes.fromhex(test_case.get("auxRand", group["auxRand"]))
            cmsg1 = bytes.fromhex(test_case["cmsg1"])
            expected_error = test_case["expectedError"]
            assert_raises(
                lambda: chilldkg.participant_step2(
                    case_hostseckey, state1, cmsg1, case_aux_rand
                ),
                expected_error,
            )
            total_cases += 1
            assert test_case["tcId"] == total_cases

    assert test_data["totalTests"] == total_cases


def test_participant_finalize_vectors():
    input_file = VECTORS_DIR / "participant_finalize_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    total_cases = 0
    for group in test_data["testGroups"]:
        # common fields for all test cases
        params = params_from_dict(group["params"])
        hostseckey = bytes.fromhex(group["hostseckey"])
        random = bytes.fromhex(group["random"])
        aux_rand = bytes.fromhex(group["auxRand"])

        # compute state1 and assert pmsg1
        state1, pmsg1 = chilldkg.participant_step1(hostseckey, params, random)
        assert bytes.fromhex(group["pmsg1"]) == pmsg1
        # compute state2 and assert pmsg2
        cmsg1 = bytes.fromhex(group["cmsg1"])
        state2, pmsg2 = chilldkg.participant_step2(hostseckey, state1, cmsg1, aux_rand)
        assert bytes.fromhex(group["pmsg2"]) == pmsg2

        for test_case in group["validTestCases"]:
            case_hostseckey = bytes.fromhex(
                test_case.get("hostseckey", group["hostseckey"])
            )
            case_random = bytes.fromhex(test_case.get("random", group["random"]))
            cmsg2 = bytes.fromhex(test_case["cmsg2"])
            rederive = case_hostseckey != hostseckey or case_random != random
            if rederive:
                case_state1, case_pmsg1 = chilldkg.participant_step1(
                    case_hostseckey, params, case_random
                )
            else:
                case_state1, case_pmsg1 = state1, pmsg1
            if "pmsg1" in test_case:
                assert case_pmsg1 == bytes.fromhex(test_case["pmsg1"])

            if rederive:
                case_state2, case_pmsg2 = chilldkg.participant_step2(
                    case_hostseckey, case_state1, cmsg1, aux_rand
                )
            else:
                case_state2, case_pmsg2 = state2, pmsg2
            if "pmsg2" in test_case:
                assert case_pmsg2 == bytes.fromhex(test_case["pmsg2"])

            psecshare, pinfo, prec = chilldkg.participant_finalize(case_state2, cmsg2)
            expected_out = test_case["expectedOutput"]
            assert bytes.fromhex(expected_out["secshare"]) == psecshare
            assert expected_out["thresholdInfo"] == threshold_info_asdict(pinfo)
            assert bytes.fromhex(expected_out["recoveryData"]) == prec
            total_cases += 1
            assert test_case["tcId"] == total_cases

        for test_case in (
            group["errorTestCases"] + group["inputValidationErrorTestCases"]
        ):
            cmsg2 = bytes.fromhex(test_case["cmsg2"])
            expected_error = test_case["expectedError"]
            assert_raises(
                lambda: chilldkg.participant_finalize(state2, cmsg2), expected_error
            )
            total_cases += 1
            assert test_case["tcId"] == total_cases

    assert test_data["totalTests"] == total_cases


def test_participant_investigate_vectors():
    input_file = VECTORS_DIR / "participant_investigate_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    total_cases = 0
    for group in test_data["testGroups"]:
        # common fields for all test cases
        params = params_from_dict(group["params"])
        hostseckey = bytes.fromhex(group["hostseckey"])
        random = bytes.fromhex(group["random"])
        aux_rand = bytes.fromhex(group["auxRand"])
        cmsg1_pool = group["cmsg1Pool"]

        # Re-derive state1
        state1, pmsg1 = chilldkg.participant_step1(hostseckey, params, random)
        assert bytes.fromhex(group["pmsg1"]) == pmsg1

        for test_case in (
            group["errorTestCases"] + group["inputValidationErrorTestCases"]
        ):
            cmsg1 = bytes.fromhex(cmsg1_pool[test_case["cmsg1Index"]])
            cinv_msg = bytes.fromhex(test_case["cinvMsg"])
            expected_error = test_case["expectedError"]
            try:
                chilldkg.participant_step2(hostseckey, state1, cmsg1, aux_rand)
            except UnknownFaultyParticipantOrCoordinatorError as e:
                assert_raises(
                    lambda e=e: chilldkg.participant_investigate(e, cinv_msg),
                    expected_error,
                )
            except Exception as e:
                raise AssertionError(f"Wrong exception raised: {type(e).__name__}")
            else:
                raise AssertionError("Expected exception")
            total_cases += 1
            assert test_case["tcId"] == total_cases

    assert test_data["totalTests"] == total_cases


def test_coordinator_step1_vectors():
    input_file = VECTORS_DIR / "coordinator_step1_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    total_cases = 0
    for group in test_data["testGroups"]:
        pmsg1_pool = group["pmsg1Pool"]

        for test_case in group["validTestCases"]:
            pmsgs1 = [bytes.fromhex(pmsg1_pool[i]) for i in test_case["pmsg1Indices"]]
            params = params_from_dict(test_case["params"])
            expected_cmsg1 = test_case["expectedCmsg1"]
            _, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)
            assert bytes.fromhex(expected_cmsg1) == cmsg1
            total_cases += 1
            assert test_case["tcId"] == total_cases

        for test_case in (
            group["errorTestCases"] + group["inputValidationErrorTestCases"]
        ):
            pmsgs1 = [bytes.fromhex(pmsg1_pool[i]) for i in test_case["pmsg1Indices"]]
            params = params_from_dict(test_case["params"])
            expected_error = test_case["expectedError"]
            assert_raises(
                lambda: chilldkg.coordinator_step1(pmsgs1, params), expected_error
            )
            total_cases += 1
            assert test_case["tcId"] == total_cases

    assert test_data["totalTests"] == total_cases


def test_coordinator_finalize_vectors():
    input_file = VECTORS_DIR / "coordinator_finalize_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    total_cases = 0

    for group in test_data["testGroups"]:
        params = params_from_dict(group["params"])
        pmsgs1 = [bytes.fromhex(m) for m in group["pmsgs1"]]
        pmsg2_pool = group["pmsg2Pool"]

        state, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)
        assert bytes.fromhex(group["cmsg1"]) == cmsg1

        for test_case in group["validTestCases"]:
            pmsgs2 = [bytes.fromhex(pmsg2_pool[i]) for i in test_case["pmsg2Indices"]]
            cmsg2, cinfo, crec = chilldkg.coordinator_finalize(state, pmsgs2)
            expected_out = test_case["expectedOutput"]
            assert bytes.fromhex(expected_out["cmsg2"]) == cmsg2
            assert expected_out["thresholdInfo"] == threshold_info_asdict(cinfo)
            assert bytes.fromhex(expected_out["recoveryData"]) == crec
            total_cases += 1
            assert test_case["tcId"] == total_cases

        for test_case in (
            group["errorTestCases"] + group["inputValidationErrorTestCases"]
        ):
            pmsgs2 = [bytes.fromhex(pmsg2_pool[i]) for i in test_case["pmsg2Indices"]]
            expected_error = test_case["expectedError"]
            assert_raises(
                lambda: chilldkg.coordinator_finalize(state, pmsgs2), expected_error
            )
            total_cases += 1
            assert test_case["tcId"] == total_cases

    assert test_data["totalTests"] == total_cases


def test_coordinator_investigate_vectors():
    input_file = VECTORS_DIR / "coordinator_investigate_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    total_cases = 0

    for group in test_data["testGroups"]:
        pmsg1_pool = group["pmsg1Pool"]

        for test_case in group["validTestCases"]:
            pmsgs1 = [bytes.fromhex(pmsg1_pool[i]) for i in test_case["pmsg1Indices"]]
            params = params_from_dict(test_case["params"])
            cinv_msgs = chilldkg.coordinator_investigate(pmsgs1, params)
            expected_cinv_msgs = test_case["expectedCinvMsgs"]
            assert [bytes.fromhex(m) for m in expected_cinv_msgs] == cinv_msgs
            total_cases += 1
            assert test_case["tcId"] == total_cases

        for test_case in (
            group["errorTestCases"] + group["inputValidationErrorTestCases"]
        ):
            pmsgs1 = [bytes.fromhex(pmsg1_pool[i]) for i in test_case["pmsg1Indices"]]
            params = params_from_dict(test_case["params"])
            expected_error = test_case["expectedError"]
            assert_raises(
                lambda: chilldkg.coordinator_investigate(pmsgs1, params),
                expected_error,
            )
            total_cases += 1
            assert test_case["tcId"] == total_cases

    assert test_data["totalTests"] == total_cases


def test_recover_vectors():
    input_file = VECTORS_DIR / "recover_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    valid_test_cases = test_data["validTestCases"]
    error_test_cases = (
        test_data["errorTestCases"] + test_data["inputValidationErrorTestCases"]
    )
    assert test_data["totalTests"] == len(valid_test_cases) + len(error_test_cases)

    for test_case in valid_test_cases:
        hostseckey = (
            bytes.fromhex(test_case["hostseckey"]) if test_case["hostseckey"] else None
        )
        recovery_data = bytes.fromhex(test_case["recoveryData"])
        expected_out = test_case["expectedOutput"]
        if hostseckey is None:
            threshold_info, params = chilldkg.coordinator_recover(recovery_data)
            assert expected_out["secshare"] is None
        else:
            secshare, threshold_info, params = chilldkg.participant_recover(
                hostseckey, recovery_data
            )
            assert bytes.fromhex(expected_out["secshare"]) == secshare
        assert expected_out["thresholdInfo"] == threshold_info_asdict(threshold_info)
        assert expected_out["params"] == params_asdict(params)

    for test_case in error_test_cases:
        hostseckey = (
            bytes.fromhex(test_case["hostseckey"]) if test_case["hostseckey"] else None
        )
        recovery_data = bytes.fromhex(test_case["recoveryData"])
        expected_error = test_case["expectedError"]
        if hostseckey is None:
            assert_raises(
                lambda: chilldkg.coordinator_recover(recovery_data), expected_error
            )
        else:
            assert_raises(
                lambda: chilldkg.participant_recover(hostseckey, recovery_data),
                expected_error,
            )


def test_recovery_acknowledgment():
    t, n = 2, 3
    hostseckeys = [random_bytes(32) for _ in range(n)]
    hostpubkeys = [chilldkg.hostpubkey_gen(hostseckey) for hostseckey in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, t)

    results = simulate_chilldkg(hostseckeys, t, investigation=False)
    recovery_data = results[1][2]  # First participant's recovery data

    ack_sigs = []
    for i in range(n):
        ack_sig = chilldkg.participant_recovery_ack_sign(
            hostseckeys[i], recovery_data, params, random_bytes(32)
        )
        assert len(ack_sig) == 64
        ack_sigs.append(ack_sig)

    chilldkg.participant_recovery_acks_verify(recovery_data, params, ack_sigs)

    # Wrong hostseckey length
    try:
        chilldkg.participant_recovery_ack_sign(
            random_bytes(16), recovery_data, params, random_bytes(32)
        )
    except ValueError:
        pass
    else:
        assert False, "Expected exception"

    # Invalid hostpubkey in params
    invalid_hostpubkey = b"\x03" + 31 * b"\x00" + b"\x05"
    invalid_params = chilldkg.SessionParams([hostpubkeys[0], invalid_hostpubkey], t)
    try:
        chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], recovery_data, invalid_params, random_bytes(32)
        )
    except chilldkg.InvalidHostPubkeyError:
        pass
    else:
        assert False, "Expected exception"

    try:
        chilldkg.participant_recovery_acks_verify(
            recovery_data, invalid_params, ack_sigs
        )
    except chilldkg.InvalidHostPubkeyError:
        pass
    else:
        assert False, "Expected exception"

    # Duplicate hostpubkey in params
    invalid_params = chilldkg.SessionParams([hostpubkeys[0], hostpubkeys[0]], t)
    try:
        chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], recovery_data, invalid_params, random_bytes(32)
        )
    except chilldkg.DuplicateHostPubkeyError:
        pass
    else:
        assert False, "Expected exception"

    # Invalid threshold in params
    invalid_params = chilldkg.SessionParams(hostpubkeys, n + 1)
    try:
        chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], recovery_data, invalid_params, random_bytes(32)
        )
    except chilldkg.ThresholdOrCountError:
        pass
    else:
        assert False, "Expected exception"

    # Wrong hostseckey
    try:
        chilldkg.participant_recovery_ack_sign(
            random_bytes(32), recovery_data, params, random_bytes(32)
        )
    except chilldkg.HostSeckeyError:
        pass
    else:
        assert False, "Expected exception"

    # Invalid randomness length
    try:
        chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], recovery_data, params, random_bytes(16)
        )
    except ValueError:
        pass
    else:
        assert False, "Expected exception"

    # Mismatched params
    invalid_params = chilldkg.SessionParams(hostpubkeys, t + 1)
    try:
        chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], recovery_data, invalid_params, random_bytes(32)
        )
    except chilldkg.RecoveryDataError:
        pass
    else:
        assert False, "Expected exception"

    try:
        chilldkg.participant_recovery_acks_verify(
            recovery_data, invalid_params, ack_sigs
        )
    except chilldkg.RecoveryDataError:
        pass
    else:
        assert False, "Expected exception"

    # Corrupted recovery data
    corrupted_recovery_data = random_bytes(len(recovery_data))
    try:
        chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], corrupted_recovery_data, params, random_bytes(32)
        )
    except chilldkg.RecoveryDataError:
        pass
    else:
        assert False, "Expected exception"

    try:
        chilldkg.participant_recovery_acks_verify(
            corrupted_recovery_data, params, ack_sigs
        )
    except chilldkg.RecoveryDataError:
        pass
    else:
        assert False, "Expected exception"

    # Invalid signature
    invalid_ack_sigs = ack_sigs[:]
    invalid_ack_sigs[1] = random_bytes(64)
    try:
        chilldkg.participant_recovery_acks_verify(
            recovery_data, params, invalid_ack_sigs
        )
    except chilldkg.InvalidRecoveryAckError as e:
        assert e.participant_id == 1
    else:
        assert False, "Expected exception"

    # Wrong signature length
    wrong_length_sigs = ack_sigs[:]
    wrong_length_sigs[0] = random_bytes(32)
    try:
        chilldkg.participant_recovery_acks_verify(
            recovery_data, params, wrong_length_sigs
        )
    except ValueError:
        pass
    else:
        assert False, "Expected exception"

    # Wrong number of signatures
    wrong_count_sigs = ack_sigs[:-1]  # n-1 instead of n
    try:
        chilldkg.participant_recovery_acks_verify(
            recovery_data, params, wrong_count_sigs
        )
    except chilldkg.LengthDoesNotMatchParamsError:
        pass
    else:
        assert False, "Expected exception"


def test_infinite_pubshare():
    # A pubshare at infinity must not make an honest party abort without blame,
    # and must never be output.
    t, n = 3, 3
    hostseckeys = [random_bytes(32) for _ in range(n)]
    params = chilldkg.SessionParams(
        [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys], t
    )
    prets1 = [
        chilldkg.participant_step1(sk, params, random_bytes(32)) for sk in hostseckeys
    ]
    pstates1 = [pret[0] for pret in prets1]

    def pubshare(cstate, i):
        return cstate.sum_coms.invalid_taproot_commit()[0].pubshare(i)

    def rush(attacker, victim):
        # After seeing all other pmsgs1, the attacker shifts its coefficient of
        # degree 1 such that the victim's pubshare becomes infinity.
        pmsgs1 = [pret[1] for pret in prets1]
        cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)
        pmsg = chilldkg.ParticipantMsg1.from_bytes(pmsgs1[attacker], t=t, n=n)
        com = pmsg.enc_pmsg.simpl_pmsg.com
        x_inv = Scalar(1) / Scalar(victim + 1)
        if attacker == victim:
            # The attacker knows its own secshare and keeps all shares valid.
            pstate2, _ = chilldkg.participant_step2(
                hostseckeys[victim], pstates1[victim], cmsg1, random_bytes(32)
            )
            delta = -Scalar.from_bytes_checked(pstate2.secshare) * x_inv
            com.ges[1] = com.ges[1] + delta * G
            for j in range(n):
                pmsg.enc_pmsg.enc_shares[j] += delta * Scalar(j + 1)
        else:
            # The attacker cannot send shares matching its commitment.
            com.ges[1] = com.ges[1] - x_inv * pubshare(cstate, victim)
        pmsgs1[attacker] = pmsg.to_bytes()
        cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)
        assert pubshare(cstate, victim).infinity
        return pmsgs1, cstate, cmsg1

    def investigate(i, cmsg1, cinvs):
        # Return a function running the investigation after participant i
        # has detected an invalid secshare.
        try:
            chilldkg.participant_step2(
                hostseckeys[i], pstates1[i], cmsg1, random_bytes(32)
            )
        except UnknownFaultyParticipantOrCoordinatorError as e:
            return lambda e=e: chilldkg.participant_investigate(e, cinvs[i])
        raise AssertionError("Expected exception")

    # Participant 2 targets participant 1's pubshare. The coordinator proceeds,
    # and all honest participants blame participant 2 via investigation.
    pmsgs1, _, cmsg1 = rush(attacker=2, victim=1)
    cinvs = chilldkg.coordinator_investigate(pmsgs1, params)
    for i in [0, 1]:
        expect_faulty_exception(
            investigate(i, cmsg1, cinvs), FaultyParticipantOrCoordinatorError, 2
        )

    # The coordinator adds D to the summed commitment of degree 1 and subtracts
    # it from the one of degree 2. This keeps participant 0's pubshare (x = 1),
    # and moves participant 1's pubshare (x = 2) by 2*D - 4*D = -pubshare to
    # infinity. Participant 0 proceeds, and the others blame the coordinator.
    pmsgs1 = [pret[1] for pret in prets1]
    cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)
    D = Scalar(1) / Scalar(2) * pubshare(cstate, 1)
    cmsg1_parsed = chilldkg.CoordinatorMsg1.from_bytes(cmsg1, t=t, n=n)
    nonconst = cmsg1_parsed.enc_cmsg.simpl_cmsg.sum_coms_to_nonconst_terms
    nonconst[0], nonconst[1] = nonconst[0] + D, nonconst[1] - D
    cmsg1 = cmsg1_parsed.to_bytes()
    cinvs = chilldkg.coordinator_investigate(pmsgs1, params)
    chilldkg.participant_step2(hostseckeys[0], pstates1[0], cmsg1, random_bytes(32))
    for i in [1, 2]:
        expect_exception(investigate(i, cmsg1, cinvs), FaultyCoordinatorError)

    # Participant 1 makes its own pubshare infinity with valid shares and
    # signs. The session is rejected in finalize and recovery.
    _, cstate, cmsg1 = rush(attacker=1, victim=1)
    pstates2 = {}
    sigs = [b""] * n
    for i in [0, 2]:
        pstates2[i], pmsg2 = chilldkg.participant_step2(
            hostseckeys[i], pstates1[i], cmsg1, random_bytes(32)
        )
        sigs[i] = chilldkg.ParticipantMsg2.from_bytes(pmsg2).sig
    eq_input = pstates2[0].eq_input
    sigs[1] = chilldkg.certeq_participant_step(
        hostseckeys[1], 1, eq_input, random_bytes(32)
    )
    pmsgs2 = [chilldkg.ParticipantMsg2(sig).to_bytes() for sig in sigs]
    expect_faulty_exception(
        lambda: chilldkg.coordinator_finalize(cstate, pmsgs2),
        FaultyParticipantError,
        1,
    )
    cert = chilldkg.certeq_coordinator_step(sigs)
    cmsg2 = chilldkg.CoordinatorMsg2(cert).to_bytes()
    for pstate2 in pstates2.values():
        expect_exception(
            lambda: chilldkg.participant_finalize(pstate2, cmsg2),
            FaultyCoordinatorError,
        )
    recovery_data = chilldkg.RecoveryData(eq_input + cert)
    expect_exception(
        lambda: chilldkg.coordinator_recover(recovery_data), chilldkg.RecoveryDataError
    )
    expect_exception(
        lambda: chilldkg.participant_recover(hostseckeys[0], recovery_data),
        chilldkg.RecoveryDataError,
    )


def test_infinite_sum_of_coms_to_secrets():
    # An infinite sum of the commitments to the secrets must not make an honest
    # party abort without blame, and must never be output.
    t, n = 2, 3
    hostseckeys = [random_bytes(32) for _ in range(n)]
    params = chilldkg.SessionParams(
        [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys], t
    )
    prets1 = [
        chilldkg.participant_step1(sk, params, random_bytes(32)) for sk in hostseckeys
    ]
    pstates1 = [pret[0] for pret in prets1]
    pmsgs1 = [pret[1] for pret in prets1]

    # The last participant replaces its commitment to the secret by the negated
    # sum of the other participants' commitments to their secrets. It doesn't
    # know the discrete logarithm of this commitment, so its pop is invalid.
    pmsgs1_parsed = [
        chilldkg.ParticipantMsg1.from_bytes(pmsg1, t=t, n=n) for pmsg1 in pmsgs1
    ]
    coms = [pmsg1.enc_pmsg.simpl_pmsg.com for pmsg1 in pmsgs1_parsed]
    coms[n - 1].ges[0] = -GE.sum(*(com.commitment_to_secret() for com in coms[:-1]))
    pmsgs1[n - 1] = pmsgs1_parsed[n - 1].to_bytes()

    # The coordinator doesn't check pops and proceeds. Honest participants
    # check the pops and blame the faulty participant.
    cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)
    for i in range(n - 1):
        expect_faulty_exception(
            lambda i=i: chilldkg.participant_step2(
                hostseckeys[i], pstates1[i], cmsg1, random_bytes(32)
            ),
            FaultyParticipantOrCoordinatorError,
            n - 1,
        )

    # If all participants sign anyway, they are all faulty. The session is
    # rejected in finalize and recovery.
    sigs = [
        chilldkg.certeq_participant_step(
            hostseckeys[i], i, cstate.eq_input, random_bytes(32)
        )
        for i in range(n)
    ]
    pmsgs2 = [chilldkg.ParticipantMsg2(sig).to_bytes() for sig in sigs]
    expect_faulty_exception(
        lambda: chilldkg.coordinator_finalize(cstate, pmsgs2),
        FaultyParticipantError,
        0,
    )
    recovery_data = chilldkg.RecoveryData(
        cstate.eq_input + chilldkg.certeq_coordinator_step(sigs)
    )
    expect_exception(
        lambda: chilldkg.coordinator_recover(recovery_data), chilldkg.RecoveryDataError
    )
    expect_exception(
        lambda: chilldkg.participant_recover(hostseckeys[0], recovery_data),
        chilldkg.RecoveryDataError,
    )


test_chilldkg_params_validate()
test_vss_correctness()
test_validate_threshold_info()
test_recovery_acknowledgment()
test_infinite_pubshare()
test_infinite_sum_of_coms_to_secrets()
for t, n in [(1, 1), (1, 2), (2, 2), (2, 3), (2, 5)]:
    test_correctness(t, n, simulate_simplpedpop)
    test_correctness(t, n, simulate_simplpedpop, investigation=True)
    test_correctness(t, n, simulate_encpedpop)
    test_correctness(t, n, simulate_encpedpop, investigation=True)
    test_correctness(t, n, simulate_chilldkg, recovery=True)
    test_correctness(t, n, simulate_chilldkg, recovery=True, investigation=True)
    test_correctness(t, n, simulate_chilldkg_full, recovery=True)
test_hostpubkey_gen_vectors()
test_params_hash_vectors()
test_participant_step1_vectors()
test_participant_step2_vectors()
test_participant_finalize_vectors()
test_participant_investigate_vectors()
test_coordinator_step1_vectors()
test_coordinator_finalize_vectors()
test_coordinator_investigate_vectors()
test_recover_vectors()
