import copy

from secp256k1lab.secp256k1 import GE, Scalar
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
    participant_finalize,
    participant_investigate,
)
from .fixtures import HOSTSECKEYS_HEX, RANDOMS_HEX, AUX_RAND_HEX
import chilldkg_ref.chilldkg as chilldkg


PARTICIPANT_STEP1_DESCRIPTION = [
    "Test vectors for participant_step1(hostseckey, params, random).",
    "Executes the first round of DKG from a participant's perspective.",
    "Takes the participant's host secret key, session parameters, and 32 bytes of fresh randomness.",
    "Returns an opaque state object and a participant message (pmsg1) to send to the coordinator.",
    "",
    "For each valid test case:",
    "  Call participant_step1(hostseckey, params, random).",
    "  Verify the returned pmsg1 equals expected_pmsg1.",
    "",
    "For each error test case:",
    "  Call participant_step1(hostseckey, params, random).",
    "  Verify it raises an exception matching expected_error.",
]


def generate_participant_step1_group():
    valid_cases = []
    error_cases = []
    tc_id = 0

    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:3])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    random = bytes.fromhex(RANDOMS_HEX[0])

    # --- Valid test case 0 ---
    tc_id += 1
    params = chilldkg.SessionParams(hostpubkeys, 2)
    _, expected_pmsg1 = chilldkg.participant_step1(hostseckeys[0], params, random)
    valid_cases.append(
        {
            "tc_id": tc_id,
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(random),
            "expected_pmsg1": bytes_to_hex(expected_pmsg1),
            "comment": "valid participant step1",
        }
    )

    # --- Error test case 0: Wrong hostseckey length ---
    tc_id += 1
    short_hostseckey = bytes.fromhex("631C047D50A67E45E27ED1FF25FCE179")
    assert len(short_hostseckey) == 16
    error = expect_exception(
        lambda: participant_step1(short_hostseckey, params, random),
        chilldkg.HostSeckeyError,
    )
    error_cases.append(
        {
            "tc_id": tc_id,
            "hostseckey": bytes_to_hex(short_hostseckey),
            "params": params_asdict(params),
            "random": bytes_to_hex(random),
            "expected_error": error,
            "comment": "length of host secret key is not 32 bytes",
        }
    )
    # --- Error test case 1: Invalid threshold ---
    tc_id += 1
    invalid_params = chilldkg.SessionParams(hostpubkeys, 0)
    error = expect_exception(
        lambda: participant_step1(hostseckeys[0], invalid_params, random),
        chilldkg.ThresholdOrCountError,
    )
    error_cases.append(
        {
            "tc_id": tc_id,
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(invalid_params),
            "random": bytes_to_hex(random),
            "expected_error": error,
            "comment": "invalid threshold value",
        }
    )
    # --- Error test case 2: hostpubkeys list contains an invalid value ---
    tc_id += 1
    invalid_hostpubkey = b"\x03" + 31 * b"\x00" + b"\x05"  # Invalid x-coordinate
    with_invalid = [hostpubkeys[0], invalid_hostpubkey, hostpubkeys[2]]
    invalid_params = chilldkg.SessionParams(with_invalid, 2)
    error = expect_exception(
        lambda: participant_step1(hostseckeys[0], invalid_params, random),
        chilldkg.InvalidHostPubkeyError,
    )
    error_cases.append(
        {
            "tc_id": tc_id,
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(invalid_params),
            "random": bytes_to_hex(random),
            "expected_error": error,
            "comment": "hostpubkeys list contains an invalid value",
        }
    )
    # --- Error test case 3: hostpubkeys list contains duplicate values ---
    tc_id += 1
    with_duplicate = [hostpubkeys[0], hostpubkeys[1], hostpubkeys[2], hostpubkeys[1]]
    duplicate_params = chilldkg.SessionParams(with_duplicate, 2)
    error = expect_exception(
        lambda: participant_step1(hostseckeys[0], duplicate_params, random),
        chilldkg.DuplicateHostPubkeyError,
    )
    error_cases.append(
        {
            "tc_id": tc_id,
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(duplicate_params),
            "random": bytes_to_hex(random),
            "expected_error": error,
            "comment": "hostpubkeys list contains duplicate values",
        }
    )
    # --- Error test case 4: hostseckey doesn't match any hostpubkey ---
    tc_id += 1
    rand_hostseckey = bytes.fromhex(
        "759DE9306FB02B3D84C455112BF1F3360401DC383ECD1FCEDE59EC809D6F9FE7"
    )
    error = expect_exception(
        lambda: participant_step1(rand_hostseckey, params, random),
        chilldkg.HostSeckeyError,
    )
    error_cases.append(
        {
            "tc_id": tc_id,
            "hostseckey": bytes_to_hex(rand_hostseckey),
            "params": params_asdict(params),
            "random": bytes_to_hex(random),
            "expected_error": error,
            "comment": "host secret key doesn't match any hostpubkey",
        }
    )
    # --- Error test case 5: Wrong randomness length ---
    tc_id += 1
    short_random = bytes.fromhex("42B53D62E27380D6F7096EDA1C28C57D")  # 16 bytes
    assert len(short_random) == 16
    error = expect_exception(
        lambda: participant_step1(hostseckeys[0], params, short_random),
        chilldkg.RandomnessError,
    )
    error_cases.append(
        {
            "tc_id": tc_id,
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(short_random),
            "expected_error": error,
            "comment": "length of randomness is not 32 bytes",
        }
    )

    return {
        "total_tests": tc_id,
        "valid_test_cases": valid_cases,
        "error_test_cases": error_cases,
    }


def generate_participant_step1_vectors():
    groups = []
    group = generate_participant_step1_group()
    tc_id = len(group["valid_test_cases"]) + len(group["error_test_cases"])
    groups.append(group)
    return {
        "description": PARTICIPANT_STEP1_DESCRIPTION,
        "total_tests": tc_id,
        "testGroups": groups,
    }


PARTICIPANT_STEP2_DESCRIPTION = [
    "Test vectors for participant_step2(hostseckey, pstate1, cmsg1, aux_rand).",
    "Executes the second round of DKG from a participant's perspective.",
    "Processes the coordinator's aggregated message (cmsg1) and produces a partial signature (pmsg2).",
    "",
    "Harness setup (re-derive state from prior round):",
    "  1. Call participant_step1(hostseckey, params, random) to obtain (pstate1, pmsg1_out).",
    "  2. Assert pmsg1_out == pmsg1 (verifies your step1 implementation before testing step2).",
    "",
    "For each valid test case:",
    "  Call participant_step2(hostseckey, pstate1, cmsg1, aux_rand).",
    "  Verify the returned pmsg2 equals expected_pmsg2.",
    "",
    "For each error test case:",
    "  Call participant_step2(hostseckey, pstate1, cmsg1, aux_rand).",
    "  Verify it raises an exception matching expected_error.",
    "  Error objects contain 'type' (exception class name) and optionally:",
    "    - 'participant': index of the blamed party (for FaultyParticipantOrCoordinatorError)",
    "    - 'message': human-readable description (informational, not required to match exactly)",
]


def generate_participant_step2_group():
    valid_cases = []
    error_cases = []
    tc_id = 0

    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:3])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, 2)
    randoms = hex_list_to_bytes(RANDOMS_HEX[:3])
    assert len(randoms) == len(hostpubkeys)
    pstates1 = []
    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        state, msg = participant_step1(hostseckeys[i], params, randoms[i])
        pstates1.append(state)
        pmsgs1.append(msg)
    _, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)
    aux_rand = bytes.fromhex(AUX_RAND_HEX)

    # --- Valid test case 0 ---
    tc_id += 1
    _, pmsg2 = participant_step2(hostseckeys[0], pstates1[0], cmsg1, aux_rand)
    valid_cases.append(
        {
            "tc_id": tc_id,
            "cmsg1": bytes_to_hex(cmsg1),
            "expected_pmsg2": bytes_to_hex(pmsg2),
            "comment": "valid participant step2",
        }
    )

    cmsg1_parsed = chilldkg.CoordinatorMsg1.from_bytes(
        cmsg1, params.t, len(params.hostpubkeys)
    )
    # --- Error Test Case 0: pubnonces list in cmsg1 has an invalid value at index 0 ---
    tc_id += 1
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.pubnonces[0] = b"\xeb" * 32  # random pubnonce
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_exception(
        lambda: participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand),
        chilldkg.FaultyCoordinatorError,
    )
    error_cases.append(
        {
            "tc_id": tc_id,
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expected_error": error,
            "comment": "invalid cmsg1: pubnonces list has an invalid value at index 0",
        }
    )
    # --- Error Test Case 1: coms_to_secret list in cmsg1 has an invalid value at index 0 ---
    tc_id += 1
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.simpl_cmsg.coms_to_secrets[0] = GE.lift_x(
        0x60C301C1EEC41AD16BF53F55F97B7B6EB842D9E2B8139712BA54695FF7116073
    )  # random GE
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_exception(
        lambda: participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand),
        chilldkg.FaultyCoordinatorError,
    )
    error_cases.append(
        {
            "tc_id": tc_id,
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expected_error": error,
            "comment": "invalid cmsg1: coms_to_secret list has an invalid value at index 0",
        }
    )
    # --- Error Test Case 2: coms_to_secret list in cmsg1 has infinity at index 1 ---
    tc_id += 1
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.simpl_cmsg.coms_to_secrets[1] = GE()  # infinity
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_exception(
        lambda: participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand),
        chilldkg.FaultyParticipantOrCoordinatorError,
    )
    error_cases.append(
        {
            "tc_id": tc_id,
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expected_error": error,
            "comment": "invalid cmsg1: coms_to_secret list has infinity at index 1",
        }
    )
    # --- Error Test Case 3: pop list in cmsg1 has an invalid value at index 1 ---
    tc_id += 1
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.simpl_cmsg.pops[1] = bytes.fromhex(
        "09C289578B96E6283AB13E4741FB489FC147FB1A5F446A314BA73C052131EFB04B83247A0BCEDF5205202AD64188B24B0BC5B51A17AEB218BD98DBE000C843B9"
    )  # random 64 bytes (not a valid signature for any key)
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_exception(
        lambda: participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand),
        chilldkg.FaultyParticipantOrCoordinatorError,
    )
    error_cases.append(
        {
            "tc_id": tc_id,
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expected_error": error,
            "comment": "invalid cmsg1: pop list has an invalid value at index 1",
        }
    )
    # --- Error Test Case 4: sum_coms_to_nonconst_terms has an invalid value at index 0 ---
    tc_id += 1
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.simpl_cmsg.sum_coms_to_nonconst_terms[0] = GE.lift_x(
        0x60C301C1EEC41AD16BF53F55F97B7B6EB842D9E2B8139712BA54695FF7116073
    )  # random GE
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_exception(
        lambda: participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand),
        chilldkg.UnknownFaultyParticipantOrCoordinatorError,
    )
    error_cases.append(
        {
            "tc_id": tc_id,
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expected_error": error,
            "comment": "invalid cmsg1: sum_coms_to_nonconst_terms has an invalid value at index 0",
        }
    )
    # --- Error Test Case 5: Participant 1 sent an invalid secshare for participant 0 ---
    tc_id += 1
    invalid_pmsgs1 = copy.deepcopy(pmsgs1)
    pmsgs11_parsed = chilldkg.ParticipantMsg1.from_bytes(
        pmsgs1[1], params.t, len(params.hostpubkeys)
    )
    pmsgs11_parsed.enc_pmsg.enc_shares[0] += Scalar(17)
    invalid_pmsgs1[1] = pmsgs11_parsed.to_bytes()
    _, invalid_cmsg1 = chilldkg.coordinator_step1(invalid_pmsgs1, params)
    error = expect_exception(
        lambda: participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand),
        chilldkg.UnknownFaultyParticipantOrCoordinatorError,
    )
    error_cases.append(
        {
            "tc_id": tc_id,
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expected_error": error,
            "comment": "invalid cmsg1: participant 1 sent an invalid secshare for participant 0",
        }
    )

    return {
        "total_tests": tc_id,
        "params": params_asdict(params),
        "hostseckey": bytes_to_hex(hostseckeys[0]),
        "random": bytes_to_hex(randoms[0]),
        "aux_rand": bytes_to_hex(aux_rand),
        "pmsg1": bytes_to_hex(pmsgs1[0]),
        "valid_test_cases": valid_cases,
        "error_test_cases": error_cases,
    }


def generate_participant_step2_vectors():
    groups = []
    group = generate_participant_step2_group()
    tc_id = len(group["valid_test_cases"]) + len(group["error_test_cases"])
    groups.append(group)
    return {
        "description": PARTICIPANT_STEP2_DESCRIPTION,
        "total_tests": tc_id,
        "testGroups": groups,
    }


PARTICIPANT_FINALIZE_DESCRIPTION = [
    "Test vectors for participant_finalize(pstate2, cmsg2).",
    "Finalizes the DKG protocol from a participant's perspective.",
    "Verifies the coordinator's certificate (cmsg2) and outputs the DKG result and recovery data.",
    "",
    "Harness setup (re-derive state through two prior rounds):",
    "  1. Call participant_step1(hostseckey, params, random) to obtain (pstate1, pmsg1_out).",
    "     Assert pmsg1_out == pmsg1.",
    "  2. Call participant_step2(hostseckey, pstate1, cmsg1, aux_rand) to obtain (pstate2, pmsg2_out).",
    "     Assert pmsg2_out == pmsg2.",
    "",
    "For each valid test case:",
    "  Call participant_finalize(pstate2, cmsg2).",
    "  Verify the result matches expected_output (dkg_output and recovery_data).",
    "",
    "For each error test case:",
    "  Call participant_finalize(pstate2, cmsg2).",
    "  Verify it raises an exception matching expected_error.",
]


def generate_participant_finalize_group():
    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:3])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, 2)
    randoms = hex_list_to_bytes(RANDOMS_HEX[:3])
    assert len(randoms) == len(hostpubkeys)
    aux_rand = bytes.fromhex(AUX_RAND_HEX)
    pstates1 = []
    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        state, msg = participant_step1(hostseckeys[i], params, randoms[i])
        pstates1.append(state)
        pmsgs1.append(msg)
    cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)

    pstates2 = []
    pmsgs2 = []
    for i in range(len(hostpubkeys)):
        state, msg = participant_step2(hostseckeys[i], pstates1[i], cmsg1, aux_rand)
        pstates2.append(state)
        pmsgs2.append(msg)

    tc_id = 0
    valid_cases = []
    error_cases = []

    vectors = {
        "params": params_asdict(params),
        "hostseckey": bytes_to_hex(hostseckeys[0]),
        "random": bytes_to_hex(randoms[0]),
        "aux_rand": bytes_to_hex(aux_rand),
        "pmsg1": bytes_to_hex(pmsgs1[0]),
        "cmsg1": bytes_to_hex(cmsg1),
        "pmsg2": bytes_to_hex(pmsgs2[0]),
    }

    # --- Valid test case 0 ---
    cmsg2, _, _ = chilldkg.coordinator_finalize(cstate, pmsgs2)
    pout, prec = participant_finalize(pstates2[0], cmsg2)

    tc_id += 1
    valid_cases.append(
        {
            "tc_id": tc_id,
            "cmsg2": bytes_to_hex(cmsg2),
            "expected_output": {
                "dkg_output": dkg_output_asdict(pout),
                "recovery_data": bytes_to_hex(prec),
            },
            "comment": "valid participant finalize",
        }
    )

    # --- Error Test Case 0: cmsg2 missing the last signature ---
    invalid_cmsg2 = chilldkg.CoordinatorMsg2(
        cmsg2[:-64]
    ).to_bytes()  # remove last signature
    error = expect_exception(
        lambda: participant_finalize(pstates2[0], invalid_cmsg2),
        chilldkg.FaultyCoordinatorError,
    )
    tc_id += 1
    error_cases.append(
        {
            "tc_id": tc_id,
            "cmsg2": bytes_to_hex(invalid_cmsg2),
            "expected_error": error,
            "comment": "invalid cmsg2: length is invalid (missing last signature)",
        }
    )

    # --- Error Test Case 1: cmsg2 has invalid signature at index 2 ---
    random_sig = bytes.fromhex(
        "09C289578B96E6283AB13E4741FB489FC147FB1A5F446A314BA73C052131EFB04B83247A0BCEDF5205202AD64188B24B0BC5B51A17AEB218BD98DBE000C843B9"
    )
    assert len(random_sig) == 64
    invalid_cmsg2_2 = chilldkg.CoordinatorMsg2(cmsg2[:-64] + random_sig).to_bytes()
    error2 = expect_exception(
        lambda: participant_finalize(pstates2[0], invalid_cmsg2_2),
        chilldkg.FaultyParticipantOrCoordinatorError,
    )
    tc_id += 1
    error_cases.append(
        {
            "tc_id": tc_id,
            "cmsg2": bytes_to_hex(invalid_cmsg2_2),
            "expected_error": error2,
            "comment": "invalid cmsg2: last signature is invalid",
        }
    )

    return {
        "total_tests": tc_id,
        "params": vectors["params"],
        "hostseckey": vectors["hostseckey"],
        "random": vectors["random"],
        "aux_rand": vectors["aux_rand"],
        "pmsg1": vectors["pmsg1"],
        "cmsg1": vectors["cmsg1"],
        "pmsg2": vectors["pmsg2"],
        "valid_test_cases": valid_cases,
        "error_test_cases": error_cases,
    }


def generate_participant_finalize_vectors():
    groups = []
    group = generate_participant_finalize_group()
    tc_id = len(group["valid_test_cases"]) + len(group["error_test_cases"])
    groups.append(group)
    return {
        "description": PARTICIPANT_FINALIZE_DESCRIPTION,
        "total_tests": tc_id,
        "testGroups": groups,
    }


PARTICIPANT_INVESTIGATE_DESCRIPTION = [
    "Test vectors for participant_investigate(error, cinv_msg).",
    "Narrows down a faulty party after participant_step2 raised UnknownFaultyParticipantOrCoordinatorError.",
    "This function always raises an exception (FaultyParticipantOrCoordinatorError or FaultyCoordinatorError).",
    "",
    "Harness setup:",
    "  1. Call participant_step1(hostseckey, params, random) to obtain (pstate1, pmsg1_out).",
    "     Assert pmsg1_out == pmsg1.",
    "  2. Per test case: look up cmsg1 from cmsg1_pool using cmsg1_index.",
    "  3. Call participant_step2(hostseckey, pstate1, cmsg1, aux_rand).",
    "     It must raise UnknownFaultyParticipantOrCoordinatorError. Capture that error object.",
    "  4. Call participant_investigate(error, cinv_msg) and verify it raises expected_error.",
    "",
    "All test cases are error cases (this function never returns successfully).",
    "Error objects contain 'type' and optionally 'participant' (index of the blamed party).",
]


def generate_participant_investigate_group():
    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:3])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, 2)
    randoms = hex_list_to_bytes(RANDOMS_HEX[:3])
    assert len(randoms) == len(hostpubkeys)
    aux_rand = bytes.fromhex(AUX_RAND_HEX)
    pstates1 = []
    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        state, msg = participant_step1(hostseckeys[i], params, randoms[i])
        pstates1.append(state)
        pmsgs1.append(msg)
    _, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)

    cmsg1_pool = []
    tc_id = 0
    error_cases = []

    # --- Error Test Case 0: Participant 1 sent an invalid secshare for participant 0 ---
    invalid_pmsgs1 = copy.deepcopy(pmsgs1)
    invalid_pmsg1_parsed = chilldkg.ParticipantMsg1.from_bytes(
        invalid_pmsgs1[1], params.t, len(params.hostpubkeys)
    )
    invalid_pmsg1_parsed.enc_pmsg.enc_shares[0] += Scalar(17)
    invalid_pmsgs1[1] = invalid_pmsg1_parsed.to_bytes()
    _, invalid_cmsg1 = chilldkg.coordinator_step1(invalid_pmsgs1, params)
    try:
        participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand)
    except chilldkg.UnknownFaultyParticipantOrCoordinatorError as e:
        cinv_msgs = chilldkg.coordinator_investigate(invalid_pmsgs1, params)
        error = expect_exception(
            lambda e=e: participant_investigate(e, cinv_msgs[0]),
            chilldkg.FaultyParticipantOrCoordinatorError,
        )
    else:
        assert False, "Expected exception"

    cmsg1_pool.append(bytes_to_hex(invalid_cmsg1))  # index 0
    tc_id += 1
    error_cases.append(
        {
            "tc_id": tc_id,
            "cmsg1_index": 0,
            "cinv_msg": bytes_to_hex(cinv_msgs[0]),
            "expected_error": error,
            "comment": "participant 1 sent an invalid secshare for participant 0",
        }
    )

    # --- Error Test Case 1: Coordinator tampered with participant 0's encrypted secshare ---
    cmsg1_parsed = chilldkg.CoordinatorMsg1.from_bytes(
        cmsg1, params.t, len(params.hostpubkeys)
    )
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_secshares[0] += Scalar(17)
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()

    try:
        participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand)
    except chilldkg.UnknownFaultyParticipantOrCoordinatorError as e:
        cinv_msgs = chilldkg.coordinator_investigate(pmsgs1, params)
        error = expect_exception(
            lambda e=e: participant_investigate(e, cinv_msgs[0]),
            chilldkg.FaultyCoordinatorError,
        )
    else:
        assert False, "Expected exception"

    cmsg1_pool.append(bytes_to_hex(invalid_cmsg1))  # index 1
    tc_id += 1
    error_cases.append(
        {
            "tc_id": tc_id,
            "cmsg1_index": 1,
            "cinv_msg": bytes_to_hex(cinv_msgs[0]),
            "expected_error": error,
            "comment": "coordinator tampered with participant 0's encrypted secshare",
        }
    )

    # --- Error Test Case 2: Coordinator tampered with self-encrypted partial secshare ---
    try:
        # using the prior invalid_cmsg1 to trigger the error
        participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand)
    except chilldkg.UnknownFaultyParticipantOrCoordinatorError as e:
        cinv_msgs = chilldkg.coordinator_investigate(pmsgs1, params)
        cinv_msg_parsed = chilldkg.CoordinatorInvestigationMsg.from_bytes(
            cinv_msgs[0], len(params.hostpubkeys)
        )
        invalid_cinv_msg0_parsed = copy.deepcopy(cinv_msg_parsed)
        invalid_cinv_msg0_parsed.enc_cinv.enc_partial_secshares[0] += Scalar(
            17
        )  # invalid share
        invalid_cinv_msg0 = invalid_cinv_msg0_parsed.to_bytes()
        error = expect_exception(
            lambda e=e: participant_investigate(e, invalid_cinv_msg0),
            chilldkg.FaultyCoordinatorError,
        )
    else:
        assert False, "Expected exception"

    tc_id += 1
    error_cases.append(
        {
            "tc_id": tc_id,
            "cmsg1_index": 1,
            "cinv_msg": bytes_to_hex(invalid_cinv_msg0),
            "expected_error": error,
            "comment": "coordinator tampered with self-encrypted partial secshare (participant 0)",
        }
    )

    # --- Error Test Case 3: partial pubshares list in cinv_msg has an invalid value at index 1 ---
    try:
        # using the prior invalid_cmsg1 to trigger the error
        participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand)
    except chilldkg.UnknownFaultyParticipantOrCoordinatorError as e:
        cinv_msgs = chilldkg.coordinator_investigate(pmsgs1, params)
        cinv_msg_parsed = chilldkg.CoordinatorInvestigationMsg.from_bytes(
            cinv_msgs[0], len(params.hostpubkeys)
        )
        invalid_cinv_msg0_parsed = copy.deepcopy(cinv_msg_parsed)
        invalid_cinv_msg0_parsed.enc_cinv.partial_pubshares[1] = GE.lift_x(
            0x60C301C1EEC41AD16BF53F55F97B7B6EB842D9E2B8139712BA54695FF7116073
        )  # random GE
        invalid_cinv_msg0 = invalid_cinv_msg0_parsed.to_bytes()
        error = expect_exception(
            lambda e=e: participant_investigate(e, invalid_cinv_msg0),
            chilldkg.FaultyCoordinatorError,
        )
    else:
        assert False, "Expected exception"

    tc_id += 1
    error_cases.append(
        {
            "tc_id": tc_id,
            "cmsg1_index": 1,
            "cinv_msg": bytes_to_hex(invalid_cinv_msg0),
            "expected_error": error,
            "comment": "partial pubshares list in cinv_msg has an invalid value at index 1",
        }
    )

    # TODO: add runtime_error test case

    return {
        "total_tests": tc_id,
        "params": params_asdict(params),
        "hostseckey": bytes_to_hex(hostseckeys[0]),
        "random": bytes_to_hex(randoms[0]),
        "aux_rand": bytes_to_hex(aux_rand),
        "pmsg1": bytes_to_hex(pmsgs1[0]),
        "cmsg1_pool": cmsg1_pool,
        "error_test_cases": error_cases,
    }


def generate_participant_investigate_vectors():
    groups = []
    group = generate_participant_investigate_group()
    tc_id = len(group["error_test_cases"])
    groups.append(group)
    return {
        "description": PARTICIPANT_INVESTIGATE_DESCRIPTION,
        "total_tests": tc_id,
        "testGroups": groups,
    }
