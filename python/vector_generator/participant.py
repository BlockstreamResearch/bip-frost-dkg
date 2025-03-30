import copy

from secp256k1lab.secp256k1 import GE, Scalar
from .util import (
    bytes_to_hex,
    hex_list_to_bytes,
    expect_exception,
    params_asdict,
    pmsg1_asdict,
    pmsg2_asdict,
    cmsg1_asdict,
    cmsg2_asdict,
    cinv_msg_asdict,
    dkg_output_asdict,
)

from chilldkg_ref.chilldkg import (
    participant_step1,
    participant_step2,
    participant_finalize,
    participant_investigate,
)
import chilldkg_ref.chilldkg as chilldkg


def generate_participant_step1_vectors():
    vectors = {"valid_test_cases": [], "error_test_cases": []}

    hostseckeys = hex_list_to_bytes(
        [
            "ADE179B2C56CB75868D44B333C16C89CB00DFDE378AD79C84D0CCE856E4F9207",
            "94BB10C1DE15783C3F3E49167A0951CACD2803F13AAC456C816E88AB4AC76330",
            "F129C2D30096C972F14BB6764CC003C97119C0E32831EA4858F0DD0DFB780FAA",
        ]
    )
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    random = bytes.fromhex(
        "42B53D62E27380D6F7096EDA1C28C57DDB89FCD4CE5B843EDAC220E165B5A7EC"
    )

    # --- Valid test case 1 ---
    params = chilldkg.SessionParams(hostpubkeys, 2)
    _, expected_pmsg1 = chilldkg.participant_step1(hostseckeys[0], params, random)
    vectors["valid_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(random),
            "expected_pmsg1": pmsg1_asdict(expected_pmsg1),
        }
    )

    # --- Error test case 1: Wrong hostseckey length ---
    short_hostseckey = bytes.fromhex("631C047D50A67E45E27ED1FF25FCE179")
    assert len(short_hostseckey) == 16
    error = expect_exception(
        lambda: participant_step1(short_hostseckey, params, random),
        chilldkg.HostSeckeyError,
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(short_hostseckey),
            "params": params_asdict(params),
            "random": bytes_to_hex(random),
            "error": error,
            "comment": "length of host secret key is not 32 bytes",
        }
    )
    # --- Error test case 2: hostseckey doesn't match any hostpubkey ---
    rand_hostseckey = bytes.fromhex(
        "759DE9306FB02B3D84C455112BF1F3360401DC383ECD1FCEDE59EC809D6F9FE7"
    )
    error = expect_exception(
        lambda: participant_step1(rand_hostseckey, params, random),
        chilldkg.HostSeckeyError,
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(rand_hostseckey),
            "params": params_asdict(params),
            "random": bytes_to_hex(random),
            "error": error,
            "comment": "host secret key doesn't match any hostpubkey",
        }
    )
    # --- Error test case 3: Invalid threshold ---
    invalid_params = chilldkg.SessionParams(hostpubkeys, 0)
    error = expect_exception(
        lambda: participant_step1(hostseckeys[0], invalid_params, random),
        chilldkg.ThresholdOrCountError,
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(invalid_params),
            "random": bytes_to_hex(random),
            "error": error,
            "comment": "invalid threshold value",
        }
    )
    # --- Error test case 4: hostpubkeys list contains duplicate values ---
    with_duplicate = [hostpubkeys[0], hostpubkeys[1], hostpubkeys[2], hostpubkeys[1]]
    duplicate_params = chilldkg.SessionParams(with_duplicate, 2)
    error = expect_exception(
        lambda: participant_step1(hostseckeys[0], duplicate_params, random),
        chilldkg.DuplicateHostPubkeyError,
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(duplicate_params),
            "random": bytes_to_hex(random),
            "error": error,
            "comment": "hostpubkeys list contains duplicate values",
        }
    )
    # --- Error test case 5: hostpubkeys list contains an invalid value ---
    invalid_hostpubkey = b"\x03" + 31 * b"\x00" + b"\x05"  # Invalid x-coordinate
    with_invalid = [hostpubkeys[0], invalid_hostpubkey, hostpubkeys[2]]
    invalid_params = chilldkg.SessionParams(with_invalid, 2)
    error = expect_exception(
        lambda: participant_step1(hostseckeys[0], invalid_params, random),
        chilldkg.InvalidHostPubkeyError,
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(invalid_params),
            "random": bytes_to_hex(random),
            "error": error,
            "comment": "hostpubkeys list contains an invalid value",
        }
    )

    return vectors


def generate_participant_step2_vectors():
    vectors = {"valid_test_cases": [], "error_test_cases": []}

    hostseckeys = hex_list_to_bytes(
        [
            "ADE179B2C56CB75868D44B333C16C89CB00DFDE378AD79C84D0CCE856E4F9207",
            "94BB10C1DE15783C3F3E49167A0951CACD2803F13AAC456C816E88AB4AC76330",
            "F129C2D30096C972F14BB6764CC003C97119C0E32831EA4858F0DD0DFB780FAA",
        ]
    )
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, 2)
    randoms = hex_list_to_bytes(
        [
            "42B53D62E27380D6F7096EDA1C28C57DDB89FCD4CE5B843EDAC220E165B5A7EC",
            "FDE223740111491D5E60BEFB447A2D8C0B12D4B1CE1A0D6BF5A16CBA7E420153",
            "E5CFC54DA8EE57BA97C389060D00BB840A9DDF6BF1E32AE3D3598373EF384EE7",
        ]
    )
    assert len(randoms) == len(hostpubkeys)
    pstates1 = []
    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        state, msg = participant_step1(hostseckeys[i], params, randoms[i])
        pstates1.append(state)
        pmsgs1.append(msg)
    _, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)

    # --- Valid test case 1 ---
    _, pmsg2 = participant_step2(hostseckeys[0], pstates1[0], cmsg1)
    vectors["valid_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(randoms[0]),
            "pmsg1": pmsg1_asdict(pmsgs1[0]),
            "cmsg1": cmsg1_asdict(cmsg1),
            "expected_pmsg2": pmsg2_asdict(pmsg2),
        }
    )

    # --- Error Test Case 1: Wrong host secret key length ---
    # short_hostseckey = bytes.fromhex("631C047D50A67E45E27ED1FF25FCE179")
    # assert len(short_hostseckey) == 16
    # error = expect_exception(
    #     lambda: participant_step2(short_hostseckey, pstates1[0], cmsg1),
    #     chilldkg.HostSeckeyError
    # )
    # vectors["error_test_cases"].append({
    #     "hostseckey": bytes_to_hex(short_hostseckey),
    #     "params": params_asdict(params),
    #     "random": bytes_to_hex(randoms[0]),
    #     "pmsg1": pmsg1_asdict(pmsgs1[0]),
    #     "cmsg1": cmsg1_asdict(cmsg1),
    #     "error": error,
    #     "comment": "length of host secret key is not 32 bytes"
    # })
    # --- Error Test Case 2: pubnonces list in cmsg1 has an invalid value at index 0 ---
    invalid_cmsg1 = copy.deepcopy(cmsg1)
    invalid_cmsg1.enc_cmsg.pubnonces[0] = b"\xeb" * 32  # random pubnonce
    error = expect_exception(
        lambda: participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1),
        chilldkg.FaultyCoordinatorError,
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(randoms[0]),
            "pmsg1": pmsg1_asdict(pmsgs1[0]),
            "cmsg1": cmsg1_asdict(invalid_cmsg1),
            "error": error,
            "comment": "pubnonces list in cmsg1 has an invalid value at index 0",
        }
    )
    # --- Error Test Case 3: coms_to_secret list in cmsg1 has an invalid value at index 0 ---
    invalid_cmsg1 = copy.deepcopy(cmsg1)
    invalid_cmsg1.enc_cmsg.simpl_cmsg.coms_to_secrets[0] = GE.lift_x(
        0x60C301C1EEC41AD16BF53F55F97B7B6EB842D9E2B8139712BA54695FF7116073
    )  # random GE
    error = expect_exception(
        lambda: participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1),
        chilldkg.FaultyCoordinatorError,
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(randoms[0]),
            "pmsg1": pmsg1_asdict(pmsgs1[0]),
            "cmsg1": cmsg1_asdict(invalid_cmsg1),
            "error": error,
            "comment": "coms_to_secret list in cmsg1 has an invalid value at index 0",
        }
    )
    # --- Error Test Case 4: coms_to_secret list in cmsg1 has infinity at index 1 ---
    invalid_cmsg1 = copy.deepcopy(cmsg1)
    invalid_cmsg1.enc_cmsg.simpl_cmsg.coms_to_secrets[1] = GE()  # infinity
    error = expect_exception(
        lambda: participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1),
        chilldkg.FaultyParticipantOrCoordinatorError,
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(randoms[0]),
            "pmsg1": pmsg1_asdict(pmsgs1[0]),
            "cmsg1": cmsg1_asdict(invalid_cmsg1),
            "error": error,
            "comment": "coms_to_secret list in cmsg1 has an invalid value at index 0",
        }
    )
    # --- Error Test Case 4: pop list in cmsg1 has an invalid value at index 1 ---
    invalid_cmsg1 = copy.deepcopy(cmsg1)
    invalid_cmsg1.enc_cmsg.simpl_cmsg.pops[1] = bytes.fromhex(
        "09C289578B96E6283AB13E4741FB489FC147FB1A5F446A314BA73C052131EFB04B83247A0BCEDF5205202AD64188B24B0BC5B51A17AEB218BD98DBE000C843B9"
    )  # random pop
    error = expect_exception(
        lambda: participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1),
        chilldkg.FaultyParticipantOrCoordinatorError,
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(randoms[0]),
            "pmsg1": pmsg1_asdict(pmsgs1[0]),
            "cmsg1": cmsg1_asdict(invalid_cmsg1),
            "error": error,
            "comment": "coms_to_secret list in cmsg1 has an invalid value at index 0",
        }
    )
    # --- Error Test Case 5: Participant 1 sent an invalid secshare for participant 0 ---
    invalid_pmsgs1 = copy.deepcopy(pmsgs1)
    invalid_pmsgs1[1].enc_pmsg.enc_shares[0] += Scalar(17)
    _, invalid_cmsg1 = chilldkg.coordinator_step1(invalid_pmsgs1, params)
    error = expect_exception(
        lambda: participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1),
        chilldkg.UnknownFaultyParticipantOrCoordinatorError,
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(randoms[0]),
            "pmsg1": pmsg1_asdict(pmsgs1[0]),
            "cmsg1": cmsg1_asdict(invalid_cmsg1),
            "error": error,
            "comment": "participant 1 sent an invalid secshare for participant 0",
        }
    )

    return vectors


def generate_participant_finalize_vectors():
    vectors = {"valid_test_cases": [], "error_test_cases": []}

    hostseckeys = hex_list_to_bytes(
        [
            "ADE179B2C56CB75868D44B333C16C89CB00DFDE378AD79C84D0CCE856E4F9207",
            "94BB10C1DE15783C3F3E49167A0951CACD2803F13AAC456C816E88AB4AC76330",
            "F129C2D30096C972F14BB6764CC003C97119C0E32831EA4858F0DD0DFB780FAA",
        ]
    )
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, 2)
    randoms = hex_list_to_bytes(
        [
            "42B53D62E27380D6F7096EDA1C28C57DDB89FCD4CE5B843EDAC220E165B5A7EC",
            "FDE223740111491D5E60BEFB447A2D8C0B12D4B1CE1A0D6BF5A16CBA7E420153",
            "E5CFC54DA8EE57BA97C389060D00BB840A9DDF6BF1E32AE3D3598373EF384EE7",
        ]
    )
    assert len(randoms) == len(hostpubkeys)
    pstates1 = []
    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        state, msg = participant_step1(hostseckeys[i], params, randoms[i])
        pstates1.append(state)
        pmsgs1.append(msg)
    cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)

    # --- Valid test case 1 ---
    pstates2 = []
    pmsgs2 = []
    for i in range(len(hostpubkeys)):
        state, msg = participant_step2(hostseckeys[i], pstates1[i], cmsg1)
        pstates2.append(state)
        pmsgs2.append(msg)
    cmsg2, cout, crec = chilldkg.coordinator_finalize(cstate, pmsgs2)
    pout, prec = participant_finalize(pstates2[0], cmsg2)
    vectors["valid_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(randoms[0]),
            "pmsg1": pmsg1_asdict(pmsgs1[0]),
            "cmsg1": cmsg1_asdict(cmsg1),
            "pmsg2": pmsg2_asdict(pmsgs2[0]),
            "cmsg2": cmsg2_asdict(cmsg2),
            "expected_output": {
                "dkg_output": dkg_output_asdict(pout),
                "recovery_data": bytes_to_hex(prec),
            },
        }
    )

    # --- Error Test Case 1: Invalid certificate length ---
    invalid_cmsg2 = chilldkg.CoordinatorMsg2(cmsg2.cert[:-64])
    error = expect_exception(
        lambda: participant_finalize(pstates2[0], invalid_cmsg2), ValueError
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(randoms[0]),
            "pmsg1": pmsg1_asdict(pmsgs1[0]),
            "cmsg1": cmsg1_asdict(cmsg1),
            "pmsg2": pmsg2_asdict(pmsgs2[0]),
            "cmsg2": cmsg2_asdict(invalid_cmsg2),
            "error": error,
            "comment": "invalid certificate length",
        }
    )
    # --- Error Test Case 2: invalid signature at index 2 ---
    random_sig = bytes.fromhex(
        "09C289578B96E6283AB13E4741FB489FC147FB1A5F446A314BA73C052131EFB04B83247A0BCEDF5205202AD64188B24B0BC5B51A17AEB218BD98DBE000C843B9"
    )
    assert len(random_sig) == 64
    invalid_cmsg2 = chilldkg.CoordinatorMsg2(cmsg2.cert[:-64] + random_sig)
    error = expect_exception(
        lambda: participant_finalize(pstates2[0], invalid_cmsg2),
        chilldkg.FaultyParticipantOrCoordinatorError,
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(randoms[0]),
            "pmsg1": pmsg1_asdict(pmsgs1[0]),
            "cmsg1": cmsg1_asdict(cmsg1),
            "pmsg2": pmsg2_asdict(pmsgs2[0]),
            "cmsg2": cmsg2_asdict(invalid_cmsg2),
            "error": error,
            "comment": "last signature (index 2) in the certificate is invalid",
        }
    )

    return vectors


def generate_participant_investigate_vectors():
    vectors = {"valid_test_cases": [], "error_test_cases": []}

    hostseckeys = hex_list_to_bytes(
        [
            "ADE179B2C56CB75868D44B333C16C89CB00DFDE378AD79C84D0CCE856E4F9207",
            "94BB10C1DE15783C3F3E49167A0951CACD2803F13AAC456C816E88AB4AC76330",
            "F129C2D30096C972F14BB6764CC003C97119C0E32831EA4858F0DD0DFB780FAA",
        ]
    )
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, 2)
    randoms = hex_list_to_bytes(
        [
            "42B53D62E27380D6F7096EDA1C28C57DDB89FCD4CE5B843EDAC220E165B5A7EC",
            "FDE223740111491D5E60BEFB447A2D8C0B12D4B1CE1A0D6BF5A16CBA7E420153",
            "E5CFC54DA8EE57BA97C389060D00BB840A9DDF6BF1E32AE3D3598373EF384EE7",
        ]
    )
    assert len(randoms) == len(hostpubkeys)
    pstates1 = []
    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        state, msg = participant_step1(hostseckeys[i], params, randoms[i])
        pstates1.append(state)
        pmsgs1.append(msg)
    _, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)

    # --- Error Test Case 1: Participant 1 sent an invalid secshare for participant 0 ---
    invalid_pmsgs1 = copy.deepcopy(pmsgs1)
    invalid_pmsgs1[1].enc_pmsg.enc_shares[0] += Scalar(17)
    _, invalid_cmsg1 = chilldkg.coordinator_step1(invalid_pmsgs1, params)
    try:
        participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1)
    except chilldkg.UnknownFaultyParticipantOrCoordinatorError as e:  # noqa: F841
        # 'e' is referenced in the lambda function below.
        # Python clears the exception variable after the except block, so ruff
        # mistakenly flags it as unused/undefined.
        cinv_msgs = chilldkg.coordinator_investigate(invalid_pmsgs1)
        error = expect_exception(
            lambda: participant_investigate(e, cinv_msgs[0]),  # noqa: F821
            chilldkg.FaultyParticipantOrCoordinatorError,
        )
    else:
        assert False, "Expected exception"
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(randoms[0]),
            "pmsg1": pmsg1_asdict(pmsgs1[0]),
            "cmsg1": cmsg1_asdict(invalid_cmsg1),
            "cinv_msg": cinv_msg_asdict(cinv_msgs[0]),
            "error": error,
            "comment": "participant 1 sent an invalid secshare for participant 0",
        }
    )
    # --- Error Test Case 2: Coordinator tampers with participant 0's encrypted secshare ---
    invalid_cmsg1 = copy.deepcopy(cmsg1)
    invalid_cmsg1.enc_secshares[0] += Scalar(17)
    try:
        participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1)
    except chilldkg.UnknownFaultyParticipantOrCoordinatorError as e:  # noqa: F841
        cinv_msgs = chilldkg.coordinator_investigate(pmsgs1)
        error = expect_exception(
            lambda: participant_investigate(e, cinv_msgs[0]),  # noqa: F821
            chilldkg.FaultyCoordinatorError,
        )
    else:
        assert False, "Expected exception"
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(randoms[0]),
            "pmsg1": pmsg1_asdict(pmsgs1[0]),
            "cmsg1": cmsg1_asdict(invalid_cmsg1),
            "cinv_msg": cinv_msg_asdict(cinv_msgs[0]),
            "error": error,
            "comment": "coordinator tampers with participant 0's encrypted secshare",
        }
    )
    # --- Error Test Case 3: Coordinator tampered with self-encrypted partial secshare ---
    try:
        # using invalid_cmsg1 to trigger the error
        participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1)
    except chilldkg.UnknownFaultyParticipantOrCoordinatorError as e:  # noqa: F841
        cinv_msgs = chilldkg.coordinator_investigate(pmsgs1)
        invalid_cinv_msg0 = copy.deepcopy(cinv_msgs[0])
        invalid_cinv_msg0.enc_cinv.enc_partial_secshares[0] += Scalar(
            17
        )  # invalid share
        error = expect_exception(
            lambda: participant_investigate(e, invalid_cinv_msg0),  # noqa: F821
            chilldkg.FaultyCoordinatorError,
        )
    else:
        assert False, "Expected exception"
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(randoms[0]),
            "pmsg1": pmsg1_asdict(pmsgs1[0]),
            "cmsg1": cmsg1_asdict(invalid_cmsg1),
            "cinv_msg": cinv_msg_asdict(invalid_cinv_msg0),
            "error": error,
            "comment": "coordinator tampered with self-encrypted partial secshare (participant 0)",
        }
    )
    # --- Error Test Case 4: partial pubshares list in cinv_msg has an invalid value at index 1 ---
    try:
        # using invalid_cmsg1 to trigger the error
        participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1)
    except chilldkg.UnknownFaultyParticipantOrCoordinatorError as e:  # noqa: F841
        cinv_msgs = chilldkg.coordinator_investigate(pmsgs1)
        invalid_cinv_msg0 = copy.deepcopy(cinv_msgs[0])
        invalid_cinv_msg0.enc_cinv.partial_pubshares[1] = GE.lift_x(
            0x60C301C1EEC41AD16BF53F55F97B7B6EB842D9E2B8139712BA54695FF7116073
        )  # random GE
        error = expect_exception(
            lambda: participant_investigate(e, invalid_cinv_msg0),  # noqa: F821
            chilldkg.FaultyCoordinatorError,
        )
    else:
        assert False, "Expected exception"
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(randoms[0]),
            "pmsg1": pmsg1_asdict(pmsgs1[0]),
            "cmsg1": cmsg1_asdict(invalid_cmsg1),
            "cinv_msg": cinv_msg_asdict(invalid_cinv_msg0),
            "error": error,
            "comment": "partial pubshares list in cinv_msg has an invalid value at index 1",
        }
    )
    # TODO: add runtime_error test case

    return vectors
