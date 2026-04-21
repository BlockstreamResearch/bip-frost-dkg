import copy
from .util import (
    bytes_to_hex,
    hex_list_to_bytes,
    expect_exception,
    params_asdict,
    dkg_output_asdict,
)

from chilldkg_ref.chilldkg import (
    participant_step1,
    participant_step2,
    coordinator_step1,
    coordinator_finalize,
    coordinator_investigate,
)
from .fixtures import HOSTSECKEYS_HEX, RANDOMS_HEX, AUX_RAND_HEX, THRESHOLD_CONFIGS
import chilldkg_ref.chilldkg as chilldkg


def generate_coordinator_step1_vectors():
    description = [
        "Test vectors for coordinator_step1(pmsgs1, params).",
        "Aggregates participant round-1 messages and produces the coordinator's broadcast message (cmsg1).",
        "",
        "Assemble the pmsgs1 list from pmsg1_pool using pmsg1_indices:",
        "  pmsgs1 = [pmsg1_pool[i] for i in pmsg1_indices]",
        "  Pool entries at indices 0..n-1 are well-formed messages; higher indices may be malformed.",
        "",
        "For each valid test case:",
        "  Call coordinator_step1(pmsgs1, params).",
        "  Verify the returned cmsg1 equals expected_cmsg1.",
        "",
        "For each error test case:",
        "  Call coordinator_step1(pmsgs1, params).",
        "  Verify it raises an exception matching expected_error.",
        "  Error objects may include 'participant' (index of the faulty party).",
    ]
    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:3])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, 2)
    randoms = hex_list_to_bytes(RANDOMS_HEX[:3])
    assert len(randoms) == len(hostpubkeys)

    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        _, msg = chilldkg.participant_step1(hostseckeys[i], params, randoms[i])
        pmsgs1.append(msg)
    _, expected_cmsg1 = coordinator_step1(pmsgs1, params)

    pmsg1_pool = []
    tc_id = 0

    # valid pmsgs1 at indices [0, 1, 2]
    for m in pmsgs1:
        pmsg1_pool.append(bytes_to_hex(m))

    valid_cases = []
    error_cases = []

    # --- Valid Test Case 0 ---
    tc_id += 1
    valid_cases.append(
        {
            "tc_id": tc_id,
            "pmsg1_indices": list(range(len(pmsgs1))),  # [0, 1, 2]
            "params": params_asdict(params),
            "expected_cmsg1": bytes_to_hex(expected_cmsg1),
            "comment": "valid coordinator step1",
        }
    )

    # --- Error Test Case 0: Invalid threshold ---
    invalid_params = chilldkg.SessionParams(hostpubkeys, 0)
    error = expect_exception(
        lambda: coordinator_step1(pmsgs1, invalid_params),
        chilldkg.ThresholdOrCountError,
    )
    tc_id += 1
    error_cases.append(
        {
            "tc_id": tc_id,
            "pmsg1_indices": list(range(len(pmsgs1))),  # same valid pmsgs1
            "params": params_asdict(invalid_params),  # t=0
            "expected_error": error,
            "comment": "invalid threshold value",
        }
    )

    # --- Error Test Case 1: hostpubkeys list contains an invalid value ---
    invalid_hostpubkey = b"\x03" + 31 * b"\x00" + b"\x05"  # Invalid x-coordinate
    with_invalid = [hostpubkeys[0], invalid_hostpubkey, hostpubkeys[2]]
    invalid_params = chilldkg.SessionParams(with_invalid, 2)
    error = expect_exception(
        lambda: coordinator_step1(pmsgs1, invalid_params),
        chilldkg.InvalidHostPubkeyError,
    )
    tc_id += 1
    error_cases.append(
        {
            "tc_id": tc_id,
            "pmsg1_indices": list(range(len(pmsgs1))),
            "params": params_asdict(invalid_params),
            "expected_error": error,
            "comment": "hostpubkeys list contains an invalid value",
        }
    )

    # --- Error Test Case 2: hostpubkeys list contains duplicate values ---
    with_duplicate = [hostpubkeys[0], hostpubkeys[1], hostpubkeys[2], hostpubkeys[1]]
    duplicate_params = chilldkg.SessionParams(with_duplicate, 2)
    error = expect_exception(
        lambda: coordinator_step1(pmsgs1, duplicate_params),
        chilldkg.DuplicateHostPubkeyError,
    )
    tc_id += 1
    error_cases.append(
        {
            "tc_id": tc_id,
            "pmsg1_indices": list(range(len(pmsgs1))),
            "params": params_asdict(duplicate_params),
            "expected_error": error,
            "comment": "hostpubkeys list contains duplicate values",
        }
    )

    # --- Error Test Case 3: Participant (index 1) message has an enc_shares list of invalid length ---
    invalid_pmsgs1 = copy.deepcopy(pmsgs1)
    invalid_pmsg1_parsed = chilldkg.ParticipantMsg1.from_bytes(
        invalid_pmsgs1[1], params.t, len(params.hostpubkeys)
    )
    invalid_pmsg1_parsed.enc_pmsg.enc_shares.pop()
    invalid_pmsgs1[1] = invalid_pmsg1_parsed.to_bytes()

    error = expect_exception(
        lambda: coordinator_step1(invalid_pmsgs1, params),
        chilldkg.FaultyParticipantError,
    )
    pmsg1_pool.append(bytes_to_hex(invalid_pmsgs1[1]))  # index 3
    tc_id += 1
    error_cases.append(
        {
            "tc_id": tc_id,
            "pmsg1_indices": [
                0,
                len(pmsg1_pool) - 1,
                2,
            ],  # [0, 3, 2] — index 1 replaced
            "params": params_asdict(params),
            "expected_error": error,
            "comment": "participant (index 1) message has an enc_shares list of invalid length",
        }
    )

    return {
        "description": description,
        "total_tests": tc_id,
        "pmsg1_pool": pmsg1_pool,
        "valid_test_cases": valid_cases,
        "error_test_cases": error_cases,
    }


def generate_coordinator_finalize_vectors():
    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:3])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, 2)
    randoms = hex_list_to_bytes(RANDOMS_HEX[:3])
    aux_rand = bytes.fromhex(AUX_RAND_HEX)
    assert len(randoms) == len(hostpubkeys)
    pstates1 = []
    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        state, msg = participant_step1(hostseckeys[i], params, randoms[i])
        pstates1.append(state)
        pmsgs1.append(msg)
    cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)

    # build pmsgs2 pool with valid messages at indices [0, 1, 2]
    pmsgs2 = []
    for i in range(len(hostpubkeys)):
        _, msg = participant_step2(hostseckeys[i], pstates1[i], cmsg1, aux_rand)
        pmsgs2.append(msg)
    cmsg2, cout, crec = coordinator_finalize(cstate, pmsgs2)
    pmsg2_pool = [bytes_to_hex(m) for m in pmsgs2]

    tc_id = 0
    valid_cases = []
    error_cases = []

    # --- Valid Test Case 0 ---
    tc_id += 1
    valid_cases.append(
        {
            "tc_id": tc_id,
            "pmsg2_indices": list(range(len(pmsgs2))),  # [0, 1, 2]
            "expected_output": {
                "cmsg2": bytes_to_hex(cmsg2),
                "dkg_output": dkg_output_asdict(cout),
                "recovery_data": bytes_to_hex(crec),
            },
            "comment": "valid coordinator finalize",
        }
    )

    # --- Error Test Case 0: short pmsgs2 (2 instead of 3) ---
    invalid_pmsgs2_short = copy.deepcopy(pmsgs2)
    invalid_pmsgs2_short.pop()
    error_case = expect_exception(
        lambda: coordinator_finalize(cstate, invalid_pmsgs2_short), ValueError
    )
    tc_id += 1
    error_cases.append(
        {
            "tc_id": tc_id,
            "pmsg2_indices": list(range(len(pmsgs2) - 1)),  # [0, 1]
            "expected_error": error_case,
            "comment": "only 2 pmsgs2 provided instead of 3",
        }
    )

    # --- Error Test Case 1: participant at index 1 sent an invalid signature ---
    invalid_pmsgs2_sig = copy.deepcopy(pmsgs2)
    invalid_pmsgs2_sig[1] = bytes.fromhex(
        "09C289578B96E6283AB13E4741FB489FC147FB1A5F446A314BA73C052131EFB04B83247A0BCEDF5205202AD64188B24B0BC5B51A17AEB218BD98DBE000C843B9"
    )  # random sig
    error_case = expect_exception(
        lambda: coordinator_finalize(cstate, invalid_pmsgs2_sig),
        chilldkg.FaultyParticipantError,
    )

    # add adversarial entry to pool
    pmsg2_pool.append(bytes_to_hex(invalid_pmsgs2_sig[1]))  # index 3
    tc_id += 1
    error_cases.append(
        {
            "tc_id": tc_id,
            "pmsg2_indices": [0, len(pmsg2_pool) - 1, 2],  # [0, 3, 2]
            "expected_error": error_case,
            "comment": "participant at index 1 sent an invalid signature",
        }
    )

    return {
        "description": [
            "Test vectors for coordinator_finalize(cstate, pmsgs2).",
            "Collects participant round-2 signatures and produces the final certificate (cmsg2).",
            "",
            "Harness setup:",
            "  1. Call coordinator_step1(pmsgs1, params) to obtain (cstate, cmsg1_out).",
            "     Assert cmsg1_out == cmsg1.",
            "",
            "Assemble the pmsgs2 list from pmsg2_pool using pmsg2_indices:",
            "  pmsgs2 = [pmsg2_pool[i] for i in pmsg2_indices]",
            "",
            "For each valid test case:",
            "  Call coordinator_finalize(cstate, pmsgs2).",
            "  Verify the result matches expected_output (cmsg2, dkg_output, recovery_data).",
            "",
            "For each error test case:",
            "  Call coordinator_finalize(cstate, pmsgs2).",
            "  Verify it raises an exception matching expected_error.",
        ],
        "total_tests": tc_id,
        "params": params_asdict(params),
        "pmsgs1": [bytes_to_hex(m) for m in pmsgs1],
        "cmsg1": bytes_to_hex(cmsg1),
        "pmsg2_pool": pmsg2_pool,
        "valid_test_cases": valid_cases,
        "error_test_cases": error_cases,
    }


def generate_coordinator_investigate_vectors():
    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:3])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, 2)
    randoms = hex_list_to_bytes(RANDOMS_HEX[:3])
    assert len(randoms) == len(hostpubkeys)

    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        _, msg = chilldkg.participant_step1(hostseckeys[i], params, randoms[i])
        pmsgs1.append(msg)
    cinv_msgs = coordinator_investigate(pmsgs1, params)

    tc_id = 0

    # --- Valid Test Case ---
    tc_id += 1
    valid_cases = [
        {
            "tc_id": tc_id,
            "expected_cinv_msgs": [bytes_to_hex(m) for m in cinv_msgs],
            "comment": "valid coordinator investigate",
        }
    ]

    return {
        "description": [
            "Test vectors for coordinator_investigate(pmsgs1, params).",
            "Generates investigation messages to help participants identify faulty parties.",
            "Called when a participant reports UnknownFaultyParticipantOrCoordinatorError.",
            "",
            "For each valid test case:",
            "  Call coordinator_investigate(pmsgs1, params).",
            "  Verify the returned list of investigation messages equals expected_cinv_msgs.",
        ],
        "total_tests": tc_id,
        "params": params_asdict(params),
        "pmsgs1": [bytes_to_hex(m) for m in pmsgs1],
        "valid_test_cases": valid_cases,
        "error_test_cases": [],
    }
