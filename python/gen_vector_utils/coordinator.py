import copy
from unittest import mock

from secp256k1lab.secp256k1 import Scalar
from secp256k1lab.util import bytes_from_int

from chilldkg_ref import chilldkg, vss

from .fixtures import AUX_RAND_HEX, HOSTSECKEYS_HEX, RANDOMS_HEX, THRESHOLD_CONFIGS
from .util import (
    assign_tc_ids,
    bytes_to_hex,
    expect_exception,
    expect_faulty_exception,
    hex_list_to_bytes,
    params_asdict,
    tg_id,
    threshold_info_asdict,
)


def participant_step1_with_zero_coeff(hostseckey, params, random, index):
    # Run participant_step1 with coefficient `index` of the participant's secret
    # polynomial set to zero. The resulting VSS commitment then contains the
    # point at infinity at position `index`, while the proof of possession, the
    # secret shares and the commitment stay consistent with each other.
    orig_generate = vss.VSS.generate

    def generate(seed, t):
        vss_ = orig_generate(seed, t)
        vss_.f.coeffs[index] = Scalar(0)
        return vss_

    with mock.patch.object(vss.VSS, "generate", staticmethod(generate)):
        return chilldkg.participant_step1(hostseckey, params, random)


COORDINATOR_STEP1_DESCRIPTION = [
    "Test vectors for coordinator_step1(pmsgs1, params).",
    "Aggregates participant round-1 messages and produces the coordinator's broadcast message (cmsg1).",
    "",
    "Assemble the pmsgs1 list from pmsg1Pool using pmsg1Indices:",
    "  pmsgs1 = [pmsg1Pool[i] for i in pmsg1Indices]",
    "  Pool entries at indices 0..n-1 are well-formed messages; higher indices may be malformed.",
    "",
    "For each valid test case:",
    "  Call coordinator_step1(pmsgs1, params).",
    "  Verify the returned cmsg1 equals expectedCmsg1.",
    "",
    "For each error test case:",
    "  Call coordinator_step1(pmsgs1, params).",
    "  Verify it raises an exception matching expectedError.",
    "  Error objects may include 'participantId' (identifier of the blamed participant).",
]


def generate_coordinator_step1_group(t, n):
    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:n])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, t)
    randoms = hex_list_to_bytes(RANDOMS_HEX[:n])
    assert len(randoms) == len(hostpubkeys)

    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        _, msg = chilldkg.participant_step1(hostseckeys[i], params, randoms[i])
        pmsgs1.append(msg)
    _, expected_cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)

    pmsg1_pool = []

    # valid pmsgs1 at indices [0, 1, ..., n - 1]
    for m in pmsgs1:
        pmsg1_pool.append(bytes_to_hex(m))

    valid_cases = []
    error_cases = []

    # --- Valid test case ---
    valid_cases.append(
        {
            "pmsg1Indices": list(range(len(pmsgs1))),  # [0, 1, ..., n - 1]
            "params": params_asdict(params),
            "expectedCmsg1": bytes_to_hex(expected_cmsg1),
            "comment": "valid coordinator step1",
        }
    )

    # --- Valid test case: participant 1's VSS commitment contains the infinity point ---
    # Participant 1's polynomial has a_1 = 0, so its commitment to that
    # coefficient is the point at infinity. For t = 1 the case is skipped,
    # so the pool indices in the comments below are one lower.
    if t >= 2:
        _, pmsg1_inf = participant_step1_with_zero_coeff(
            hostseckeys[1], params, randoms[1], 1
        )
        assert pmsg1_inf[33:66] == 33 * b"\x00"  # com[1] encodes infinity
        pmsgs1_inf = list(pmsgs1)
        pmsgs1_inf[1] = pmsg1_inf
        _, cmsg1_inf = chilldkg.coordinator_step1(pmsgs1_inf, params)

        pmsg1_pool.append(bytes_to_hex(pmsg1_inf))  # index n
        valid_cases.append(
            {
                "pmsg1Indices": [
                    len(pmsg1_pool) - 1 if i == 1 else i for i in range(n)
                ],  # [0, n, 2,..., n - 1] — index 1 replaced
                "params": params_asdict(params),
                "expectedCmsg1": bytes_to_hex(cmsg1_inf),
                "comment": "participant 1's VSS commitment contains the infinity point (a_1 = 0)",
            }
        )

    # --- Error test case: Invalid threshold ---
    invalid_params = chilldkg.SessionParams(hostpubkeys, 0)
    error = expect_exception(
        lambda: chilldkg.coordinator_step1(pmsgs1, invalid_params),
        chilldkg.ThresholdOrCountError,
    )
    error_cases.append(
        {
            "pmsg1Indices": list(range(len(pmsgs1))),  # same valid pmsgs1
            "params": params_asdict(invalid_params),  # t=0
            "expectedError": error,
            "comment": "invalid threshold value",
        }
    )

    # --- Error test case: t > n ---
    invalid_params = chilldkg.SessionParams(hostpubkeys, n + 1)
    error = expect_exception(
        lambda: chilldkg.coordinator_step1(pmsgs1, invalid_params),
        chilldkg.ThresholdOrCountError,
    )
    error_cases.append(
        {
            "pmsg1Indices": list(range(len(pmsgs1))),  # same valid pmsgs1
            "params": params_asdict(invalid_params),  # t = n + 1
            "expectedError": error,
            "comment": "invalid threshold value t > n",
        }
    )

    # --- Error test case: hostpubkeys list contains an invalid value ---
    invalid_hostpubkey = b"\x03" + 31 * b"\x00" + b"\x05"  # Invalid x-coordinate
    with_invalid = hostpubkeys[:-1] + [invalid_hostpubkey]
    invalid_params = chilldkg.SessionParams(with_invalid, t)
    error = expect_exception(
        lambda: chilldkg.coordinator_step1(pmsgs1, invalid_params),
        chilldkg.InvalidHostPubkeyError,
    )
    error_cases.append(
        {
            "pmsg1Indices": list(range(len(pmsgs1))),
            "params": params_asdict(invalid_params),
            "expectedError": error,
            "comment": "hostpubkeys list contains an invalid value",
        }
    )

    # --- Error test case: hostpubkeys list contains duplicate values ---
    with_duplicate = hostpubkeys[:-1] + [hostpubkeys[0]]
    duplicate_params = chilldkg.SessionParams(with_duplicate, t)
    error = expect_exception(
        lambda: chilldkg.coordinator_step1(pmsgs1, duplicate_params),
        chilldkg.DuplicateHostPubkeyError,
    )
    error_cases.append(
        {
            "pmsg1Indices": list(range(len(pmsgs1))),
            "params": params_asdict(duplicate_params),
            "expectedError": error,
            "comment": "hostpubkeys list contains duplicate values",
        }
    )

    # --- Error test case: hostpubkeys list contains infinite value ---
    infinity_hostpubkey = b"\x00" * 33  # Infinite point
    with_infinity = hostpubkeys[:-1] + [infinity_hostpubkey]
    invalid_params = chilldkg.SessionParams(with_infinity, t)
    error = expect_exception(
        lambda: chilldkg.coordinator_step1(pmsgs1, invalid_params),
        chilldkg.InvalidHostPubkeyError,
    )
    error_cases.append(
        {
            "pmsg1Indices": list(range(len(pmsgs1))),
            "params": params_asdict(invalid_params),
            "expectedError": error,
            "comment": "hostpubkeys list contains an infinity point",
        }
    )

    # --- Error test case: invalid pmsgs1 (n-1 entries instead of n) ---
    short_pmsgs1 = pmsgs1[: n - 1]
    error = expect_exception(
        lambda: chilldkg.coordinator_step1(short_pmsgs1, params),
        ValueError,
    )
    error_cases.append(
        {
            "pmsg1Indices": list(range(n - 1)),
            "params": params_asdict(params),
            "expectedError": error,
            "comment": "invalid pmsgs1: fewer entries than participants",
        }
    )

    # --- Error test case: invalid pmsgs1 (n+1 entries instead of n) ---
    long_pmsgs1 = pmsgs1 + [pmsgs1[0]]  # Add an extra entry
    error = expect_exception(
        lambda: chilldkg.coordinator_step1(long_pmsgs1, params),
        ValueError,
    )
    error_cases.append(
        {
            "pmsg1Indices": list(range(n)) + [0],
            "params": params_asdict(params),
            "expectedError": error,
            "comment": "invalid pmsgs1: more entries than participants",
        }
    )

    # --- Error test case: participant (id 1) message has an enc_shares list of invalid length ---
    invalid_pmsgs1 = copy.deepcopy(pmsgs1)
    invalid_pmsg1_parsed = chilldkg.ParticipantMsg1.from_bytes(
        invalid_pmsgs1[1], t=params.t, n=len(params.hostpubkeys)
    )
    invalid_pmsg1_parsed.enc_pmsg.enc_shares.pop()
    invalid_pmsgs1[1] = invalid_pmsg1_parsed.to_bytes()

    error = expect_exception(
        lambda: chilldkg.coordinator_step1(invalid_pmsgs1, params),
        ValueError,
    )
    pmsg1_pool.append(bytes_to_hex(invalid_pmsgs1[1]))  # index n + 1
    error_cases.append(
        {
            "pmsg1Indices": [
                len(pmsg1_pool) - 1 if i == 1 else i for i in range(n)
            ],  # [0, n + 1, 2,..., n - 1] — index 1 replaced
            "params": params_asdict(params),
            "expectedError": error,
            "comment": "participant (id 1) message has an enc_shares list of invalid length",
        }
    )

    # --- Error test case: participant (index 1) message has an out-of-range enc_share ---
    overflow = bytes_from_int(Scalar.SIZE)  # 32 bytes
    valid_pmsg1 = pmsgs1[1]
    invalid_pmsg1 = (
        valid_pmsg1[: -32 * n]
        + overflow
        + valid_pmsg1[len(valid_pmsg1) - 32 * (n - 1) :]
    )
    invalid_pmsgs1 = list(pmsgs1)
    invalid_pmsgs1[1] = invalid_pmsg1
    error = expect_faulty_exception(
        lambda: chilldkg.coordinator_step1(invalid_pmsgs1, params),
        chilldkg.FaultyParticipantError,
        1,
    )
    pmsg1_pool.append(bytes_to_hex(invalid_pmsg1))  # index n + 2
    error_cases.append(
        {
            "pmsg1Indices": [
                len(pmsg1_pool) - 1 if i == 1 else i for i in range(n)
            ],  # [0, n + 2, 2,..., n - 1] — index 1 replaced
            "params": params_asdict(params),
            "expectedError": error,
            "comment": "participant (index 1) message has an out-of-range enc_share",
        }
    )

    # --- Error test case: participant (index 1) message has an off-curve x-coordinate in the VSS commitment ---
    off_curve = b"\x03" + 31 * b"\x00" + b"\x05"
    valid_pmsg1 = pmsgs1[1]
    invalid_pmsg1 = off_curve + valid_pmsg1[33:]
    invalid_pmsgs1 = list(pmsgs1)
    invalid_pmsgs1[1] = invalid_pmsg1
    error = expect_faulty_exception(
        lambda: chilldkg.coordinator_step1(invalid_pmsgs1, params),
        chilldkg.FaultyParticipantError,
        1,
    )
    pmsg1_pool.append(bytes_to_hex(invalid_pmsg1))  # index n + 3
    error_cases.append(
        {
            "pmsg1Indices": [
                len(pmsg1_pool) - 1 if i == 1 else i for i in range(n)
            ],  # [0, n + 3, 2,..., n - 1] — index 1 replaced
            "params": params_asdict(params),
            "expectedError": error,
            "comment": "participant (index 1) message has an off-curve x-coordinate in the VSS commitment",
        }
    )

    # --- Error test case: pmsg1 (index 0) is empty ---
    empty_pmsgs1 = b""
    pmsg1_pool.append(bytes_to_hex(empty_pmsgs1))  # index n + 4
    invalid_pmsgs1 = [empty_pmsgs1] + pmsgs1[1:]
    error = expect_exception(
        lambda: chilldkg.coordinator_step1(invalid_pmsgs1, params),
        ValueError,
    )
    error_cases.append(
        {
            "pmsg1Indices": [
                len(pmsg1_pool) - 1 if i == 0 else i for i in range(n)
            ],  # [n + 4, 1, 2,..., n - 1] — index 0 replaced
            "params": params_asdict(params),
            "expectedError": error,
            "comment": "missing simplpedpop participant message at index 0",
        }
    )

    # --- Error test case: pmsg1 (index 1) truncated before pubnonce ---
    simpl_pmsg_len = 33 * params.t + 64
    truncated_pmsg1 = pmsgs1[1][:simpl_pmsg_len]
    pmsg1_pool.append(bytes_to_hex(truncated_pmsg1))  # index n + 5
    invalid_pmsgs1 = list(pmsgs1)
    invalid_pmsgs1[1] = truncated_pmsg1
    error = expect_exception(
        lambda: chilldkg.coordinator_step1(invalid_pmsgs1, params),
        ValueError,
    )
    error_cases.append(
        {
            "pmsg1Indices": [
                len(pmsg1_pool) - 1 if i == 1 else i for i in range(n)
            ],  # [0, n + 5, 2,..., n - 1] — index 1 replaced
            "params": params_asdict(params),
            "expectedError": error,
            "comment": "missing public nonce in pmsg1 (index 1)",
        }
    )

    return {
        "tgId": tg_id(t, n),
        "pmsg1Pool": pmsg1_pool,
        "validTestCases": valid_cases,
        "errorTestCases": error_cases,
    }


def generate_coordinator_step1_vectors():
    groups = [generate_coordinator_step1_group(t, n) for t, n in THRESHOLD_CONFIGS]
    total_tests = assign_tc_ids(groups)
    return {
        "description": COORDINATOR_STEP1_DESCRIPTION,
        "totalTests": total_tests,
        "testGroups": groups,
    }


COORDINATOR_FINALIZE_DESCRIPTION = [
    "Test vectors for coordinator_finalize(cstate, pmsgs2).",
    "Collects participant round-2 signatures and produces the final certificate (cmsg2).",
    "",
    "Harness setup:",
    "  1. Call coordinator_step1(pmsgs1, params) to obtain (cstate, cmsg1_out).",
    "     Assert cmsg1_out == cmsg1.",
    "",
    "Assemble the pmsgs2 list from pmsg2Pool using pmsg2Indices:",
    "  pmsgs2 = [pmsg2Pool[i] for i in pmsg2Indices]",
    "",
    "For each valid test case:",
    "  Call coordinator_finalize(cstate, pmsgs2).",
    "  Verify the result matches expectedOutput (cmsg2, thresholdInfo, recoveryData).",
    "",
    "For each error test case:",
    "  Call coordinator_finalize(cstate, pmsgs2).",
    "  Verify it raises an exception matching expectedError.",
]


def generate_coordinator_finalize_group(t, n):
    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:n])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, t)
    randoms = hex_list_to_bytes(RANDOMS_HEX[:n])
    aux_rand = bytes.fromhex(AUX_RAND_HEX)
    assert len(randoms) == len(hostpubkeys)
    pstates1 = []
    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        state, msg = chilldkg.participant_step1(hostseckeys[i], params, randoms[i])
        pstates1.append(state)
        pmsgs1.append(msg)
    cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)

    # build pmsgs2 pool with valid messages at indices [0, 1, ..., n - 1]
    pmsgs2 = []
    for i in range(len(hostpubkeys)):
        _, msg = chilldkg.participant_step2(
            hostseckeys[i], pstates1[i], cmsg1, aux_rand
        )
        pmsgs2.append(msg)
    cmsg2, cinfo, crec = chilldkg.coordinator_finalize(cstate, pmsgs2)
    pmsg2_pool = [bytes_to_hex(m) for m in pmsgs2]

    valid_cases = []
    error_cases = []

    # --- Valid test case ---
    valid_cases.append(
        {
            "pmsg2Indices": list(range(len(pmsgs2))),  # [0, 1, ..., n - 1]
            "expectedOutput": {
                "cmsg2": bytes_to_hex(cmsg2),
                "thresholdInfo": threshold_info_asdict(cinfo),
                "recoveryData": bytes_to_hex(crec),
            },
            "comment": "valid coordinator finalize",
        }
    )

    # --- Error test case: participant with id 1 has a short signature ---
    invalid_pmsgs2_short_sig = copy.deepcopy(pmsgs2)
    invalid_pmsgs2_short_sig[1] = invalid_pmsgs2_short_sig[1][
        :63
    ]  # truncate sig to 63 bytes
    error_case = expect_exception(
        lambda: chilldkg.coordinator_finalize(cstate, invalid_pmsgs2_short_sig),
        ValueError,
    )
    pmsg2_pool.append(bytes_to_hex(invalid_pmsgs2_short_sig[1]))  # index n
    error_cases.append(
        {
            "pmsg2Indices": [
                len(pmsg2_pool) - 1 if i == 1 else i for i in range(n)
            ],  # [0, n, 2, ..., n-1] — index 1 replaced with bad pmsg
            "expectedError": error_case,
            "comment": "participant with id 1 sent a short signature",
        }
    )

    # --- Error test case: invalid pmsgs2 (n-1 entries instead of n) ---
    invalid_pmsgs2_short = copy.deepcopy(pmsgs2)
    invalid_pmsgs2_short.pop()
    error_case = expect_exception(
        lambda: chilldkg.coordinator_finalize(cstate, invalid_pmsgs2_short), ValueError
    )
    error_cases.append(
        {
            "pmsg2Indices": list(range(len(pmsgs2) - 1)),  # [0, ..., n - 2]
            "expectedError": error_case,
            "comment": "invalid pmsgs2: fewer entries than participants",
        }
    )

    # --- Error test case: invalid pmsgs2 (n+1 entries instead of n) ---
    invalid_pmsgs2_long = pmsgs2 + [pmsgs2[0]]
    error_case = expect_exception(
        lambda: chilldkg.coordinator_finalize(cstate, invalid_pmsgs2_long), ValueError
    )
    error_cases.append(
        {
            "pmsg2Indices": list(range(len(pmsgs2))) + [0],  # [0, 1, ..., n-1, 0]
            "expectedError": error_case,
            "comment": "invalid pmsgs2: more entries than participants",
        }
    )

    # --- Error test case: participant with id 1 sent an invalid signature ---
    invalid_pmsgs2_sig = copy.deepcopy(pmsgs2)
    invalid_pmsgs2_sig[1] = bytes.fromhex(
        "09C289578B96E6283AB13E4741FB489FC147FB1A5F446A314BA73C052131EFB04B83247A0BCEDF5205202AD64188B24B0BC5B51A17AEB218BD98DBE000C843B9"
    )  # random sig
    error_case = expect_faulty_exception(
        lambda: chilldkg.coordinator_finalize(cstate, invalid_pmsgs2_sig),
        chilldkg.FaultyParticipantError,
        1,
    )

    # add adversarial entry to pool
    pmsg2_pool.append(bytes_to_hex(invalid_pmsgs2_sig[1]))  # index n + 1
    error_cases.append(
        {
            "pmsg2Indices": [
                len(pmsg2_pool) - 1 if i == 1 else i for i in range(n)
            ],  # [0, n + 1, 2,..., n - 1]
            "expectedError": error_case,
            "comment": "participant with id 1 sent an invalid signature",
        }
    )

    return {
        "tgId": tg_id(t, n),
        "params": params_asdict(params),
        "pmsgs1": [bytes_to_hex(m) for m in pmsgs1],
        "cmsg1": bytes_to_hex(cmsg1),
        "pmsg2Pool": pmsg2_pool,
        "validTestCases": valid_cases,
        "errorTestCases": error_cases,
    }


def generate_coordinator_finalize_vectors():
    groups = [generate_coordinator_finalize_group(t, n) for t, n in THRESHOLD_CONFIGS]
    total_tests = assign_tc_ids(groups)
    return {
        "description": COORDINATOR_FINALIZE_DESCRIPTION,
        "totalTests": total_tests,
        "testGroups": groups,
    }


COORDINATOR_INVESTIGATE_DESCRIPTION = [
    "Test vectors for coordinator_investigate(pmsgs1, params).",
    "Generates investigation messages to help participants identify faulty parties.",
    "Called when a participant reports UnknownFaultyParticipantOrCoordinatorError.",
    "",
    "For each valid test case:",
    "  Call coordinator_investigate(pmsgs1, params).",
    "  Verify the returned list of investigation messages equals expectedCinvMsgs.",
]


def generate_coordinator_investigate_group(t, n):
    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:n])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, t)
    randoms = hex_list_to_bytes(RANDOMS_HEX[:n])
    assert len(randoms) == len(hostpubkeys)

    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        _, msg = chilldkg.participant_step1(hostseckeys[i], params, randoms[i])
        pmsgs1.append(msg)
    cinv_msgs = chilldkg.coordinator_investigate(pmsgs1, params)

    # --- Valid test case ---
    valid_cases = [
        {
            "expectedCinvMsgs": [bytes_to_hex(m) for m in cinv_msgs],
            "comment": "valid coordinator investigate",
        }
    ]

    return {
        "tgId": tg_id(t, n),
        "params": params_asdict(params),
        "pmsgs1": [bytes_to_hex(m) for m in pmsgs1],
        "validTestCases": valid_cases,
        "errorTestCases": [],
    }


def generate_coordinator_investigate_vectors():
    groups = [
        generate_coordinator_investigate_group(t, n) for t, n in THRESHOLD_CONFIGS
    ]
    total_tests = assign_tc_ids(groups)
    return {
        "description": COORDINATOR_INVESTIGATE_DESCRIPTION,
        "totalTests": total_tests,
        "testGroups": groups,
    }
