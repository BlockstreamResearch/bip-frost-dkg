from secp256k1lab.secp256k1 import Scalar
from secp256k1lab.util import bytes_from_int
from .util import (
    bytes_to_hex,
    hex_list_to_bytes,
    expect_exception,
    params_asdict,
    dkg_output_asdict,
)

from chilldkg_ref.chilldkg import hostpubkey_gen, params_id, recover
import chilldkg_ref.chilldkg as chilldkg


def generate_hostpubkey_vectors():
    vectors = {"valid_test_cases": [], "error_test_cases": []}

    # --- Valid test case 1 ---
    hostseckey = bytes.fromhex(
        "631C047D50A67E45E27ED1FF25FCE179CAF059A2120D346ACD9774C1F2BAB66F"
    )
    expected_pubkey = hostpubkey_gen(hostseckey)
    vectors["valid_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckey),
            "expected_hostpubkey": bytes_to_hex(expected_pubkey),
            "comment": "valid host secret key",
        }
    )

    # --- Error test case 1: Wrong length ---
    short_hostseckey = bytes.fromhex("631C047D50A67E45E27ED1FF25FCE179")
    assert len(short_hostseckey) == 16
    error = expect_exception(
        lambda: hostpubkey_gen(short_hostseckey), chilldkg.HostSeckeyError
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(short_hostseckey),
            "error": error,
            "comment": "length of host secret key is not 32 bytes",
        }
    )
    # --- Error test case 2: Out-of-range hostseckey (Scalar.ORDER) ---
    invalid_hostseckey = bytes_from_int(Scalar.SIZE)
    error = expect_exception(lambda: hostpubkey_gen(invalid_hostseckey), ValueError)
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(invalid_hostseckey),
            "error": error,
            "comment": "host secret key is out of range",
        }
    )
    # --- Error test case 3: zeroed hostseckey ---
    zeroed_hostseckey = b"\x00" * 32
    error = expect_exception(lambda: hostpubkey_gen(zeroed_hostseckey), ValueError)
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(zeroed_hostseckey),
            "error": error,
            "comment": "zeroed host secret key",
        }
    )

    return vectors


def generate_params_id_vectors():
    vectors = {"valid_test_cases": [], "error_test_cases": []}
    hostseckeys = hex_list_to_bytes(
        [
            "ADE179B2C56CB75868D44B333C16C89CB00DFDE378AD79C84D0CCE856E4F9207",
            "94BB10C1DE15783C3F3E49167A0951CACD2803F13AAC456C816E88AB4AC76330",
            "F129C2D30096C972F14BB6764CC003C97119C0E32831EA4858F0DD0DFB780FAA",
        ]
    )
    hostpubkeys = [hostpubkey_gen(sk) for sk in hostseckeys]

    # --- Valid test cases ---
    valid_cases = [
        {"t": 2, "comment": ""},
        {"t": 1, "comment": "min threshold value"},
        {"t": len(hostpubkeys), "comment": "max threshold value"},
    ]

    for case in valid_cases:
        t = case["t"]
        params = chilldkg.SessionParams(hostpubkeys, t)
        expected_params_id = params_id(params)
        test_case = {
            "params": params_asdict(params),
            "expected_params_id": bytes_to_hex(expected_params_id),
        }
        if case["comment"]:
            test_case["comment"] = case["comment"]
        vectors["valid_test_cases"].append(test_case)

    # --- Error test case 1: Invalid threshold ---
    t = 0
    invalid_params = chilldkg.SessionParams(hostpubkeys, t)
    error = expect_exception(
        lambda: params_id(invalid_params), chilldkg.ThresholdOrCountError
    )
    vectors["error_test_cases"].append(
        {
            "params": params_asdict(invalid_params),
            "error": error,
            "comment": "invalid threshold value",
        }
    )
    # --- Error test case 2: hostpubkeys list contains duplicate values ---
    t = 2
    with_duplicate = [hostpubkeys[0], hostpubkeys[1], hostpubkeys[2], hostpubkeys[1]]
    duplicate_params = chilldkg.SessionParams(with_duplicate, t)
    error = expect_exception(
        lambda: params_id(duplicate_params), chilldkg.DuplicateHostPubkeyError
    )
    vectors["error_test_cases"].append(
        {
            "params": params_asdict(duplicate_params),
            "error": error,
            "comment": "hostpubkeys list contains duplicate values",
        }
    )
    # --- Error test case 2: hostpubkeys list contains an invalid value ---
    invalid_hostpubkey = b"\x03" + 31 * b"\x00" + b"\x05"  # Invalid x-coordinate
    t = 2
    with_invalid = [hostpubkeys[0], invalid_hostpubkey, hostpubkeys[2]]
    invalid_params = chilldkg.SessionParams(with_invalid, t)
    error = expect_exception(
        lambda: params_id(invalid_params), chilldkg.InvalidHostPubkeyError
    )
    vectors["error_test_cases"].append(
        {
            "params": params_asdict(invalid_params),
            "error": error,
            "comment": "hostpubkeys list contains an invalid value",
        }
    )

    return vectors


def generate_recover_vectors():
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
        state, msg = chilldkg.participant_step1(hostseckeys[i], params, randoms[i])
        pstates1.append(state)
        pmsgs1.append(msg)
    cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)

    pstates2 = []
    pmsgs2 = []
    for i in range(len(hostpubkeys)):
        state, msg = chilldkg.participant_step2(hostseckeys[i], pstates1[i], cmsg1)
        pstates2.append(state)
        pmsgs2.append(msg)
    cmsg2, cout, crec = chilldkg.coordinator_finalize(cstate, pmsgs2)
    pout, prec = chilldkg.participant_finalize(pstates2[0], cmsg2)
    assert prec == crec

    # --- Valid test case 1: participant recovery ---
    pout_rec, params_rec = recover(hostseckeys[0], prec)
    assert pout_rec == pout
    assert params_rec == params
    vectors["valid_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "recovery_data": bytes_to_hex(prec),
            "expected_output": {
                "dkg_output": dkg_output_asdict(pout_rec),
                "params": params_asdict(params_rec),
            },
            "comment": "participant recovery",
        }
    )
    # --- Valid test case 2: coordinator recovery ---
    cout_rec, params_rec = recover(None, crec)
    assert cout_rec == cout
    assert params_rec == params
    vectors["valid_test_cases"].append(
        {
            "hostseckey": None,
            "recovery_data": bytes_to_hex(crec),
            "expected_output": {
                "dkg_output": dkg_output_asdict(cout_rec),
                "params": params_asdict(params_rec),
            },
            "comment": "coordinator recovery",
        }
    )

    # --- Error test case 1: recovery data of invalid length ---
    invalid_crec = crec[1:]
    error = expect_exception(
        lambda: recover(None, invalid_crec), chilldkg.RecoveryDataError
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": None,
            "recovery_data": bytes_to_hex(invalid_crec),
            "error": error,
            "comment": "recovery data of invalid length",
        }
    )
    # --- Error test case 2: first coefficient of sum_coms is invalid ---
    invalid_ge = b"\x03" + 31 * b"\x00" + b"\x05"  # Invalid x-coordinate
    invalid_crec = crec[:4] + invalid_ge + crec[4 + 33 :]
    error = expect_exception(
        lambda: recover(None, invalid_crec), chilldkg.RecoveryDataError
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": None,
            "recovery_data": bytes_to_hex(invalid_crec),
            "error": error,
            "comment": "first coefficient of sum_coms is invalid",
        }
    )
    # --- Error test case 3: last share in enc_secshare list is out of range ---
    n = len(hostpubkeys)
    cert_len = chilldkg.certeq_cert_len(n)
    rand_encshare = bytes.fromhex(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
    )
    invalid_crec = crec[: -cert_len - 32] + rand_encshare + crec[-cert_len:]
    error = expect_exception(
        lambda: recover(None, invalid_crec), chilldkg.RecoveryDataError
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": None,
            "recovery_data": bytes_to_hex(invalid_crec),
            "error": error,
            "comment": "last share in enc_secshare list is invalid",
        }
    )
    # --- Error test case 4: invalid threshold ---
    invalid_crec = b"\x00" * 4 + crec[4:]
    error = expect_exception(
        lambda: recover(None, invalid_crec), chilldkg.RecoveryDataError
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": None,
            "recovery_data": bytes_to_hex(invalid_crec),
            "error": error,
            "comment": "invalid threshold",
        }
    )
    # --- Error test case 5: first pubkey in the hostpubkey list is invalid ---
    t = params.t
    invalid_ge = b"\x03" + 31 * b"\x00" + b"\x05"
    invalid_crec = crec[: 4 + 33 * t] + invalid_ge + crec[4 + 33 * t + 33 :]
    error = expect_exception(
        lambda: recover(None, invalid_crec), chilldkg.RecoveryDataError
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": None,
            "recovery_data": bytes_to_hex(invalid_crec),
            "error": error,
            "comment": "invalid threshold",
        }
    )
    # --- Error test case 6: last pubnonce in the pubnonces list is invalid ---
    n = len(hostpubkeys)
    cert_len = chilldkg.certeq_cert_len(n)
    rand_ge = bytes.fromhex(
        "03421F5FC9A21065445C96FDB91C0C1E2F2431741C72713B4B99DDCB316F31E9FC"
    )
    invalid_crec = (
        crec[: -cert_len - 32 * n - 33] + rand_ge + crec[-cert_len - 32 * n :]
    )
    error = expect_exception(
        lambda: recover(None, invalid_crec), chilldkg.RecoveryDataError
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": None,
            "recovery_data": bytes_to_hex(invalid_crec),
            "error": error,
            "comment": "last pubnonce in the pubnonces list is invalid",
        }
    )
    # --- Error test case 6: last signature in the certificate is invalid ---
    rand_sig = bytes.fromhex(
        "09C289578B96E6283AB13E4741FB489FC147FB1A5F446A314BA73C052131EFB04B83247A0BCEDF5205202AD64188B24B0BC5B51A17AEB218BD98DBE000C843B9"
    )
    invalid_crec = crec[:-64] + rand_sig
    error = expect_exception(
        lambda: recover(None, invalid_crec), chilldkg.RecoveryDataError
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": None,
            "recovery_data": bytes_to_hex(invalid_crec),
            "error": error,
            "comment": "last signature in the certificate is invalid",
        }
    )
    # --- Error test case 7: invalid hostseckey ---
    short_hostseckey = bytes.fromhex("631C047D50A67E45E27ED1FF25FCE179")
    assert len(short_hostseckey) == 16
    error = expect_exception(
        lambda: recover(short_hostseckey, crec), chilldkg.HostSeckeyError
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(short_hostseckey),
            "recovery_data": bytes_to_hex(crec),
            "error": error,
            "comment": "invalid hostseckey",
        }
    )
    # --- Error test case 8: hostseckey doesn't match any hostpubkey ---
    rand_hostseckey = bytes.fromhex(
        "759DE9306FB02B3D84C455112BF1F3360401DC383ECD1FCEDE59EC809D6F9FE7"
    )
    error = expect_exception(
        lambda: recover(rand_hostseckey, crec), chilldkg.HostSeckeyError
    )
    vectors["error_test_cases"].append(
        {
            "hostseckey": bytes_to_hex(rand_hostseckey),
            "recovery_data": bytes_to_hex(crec),
            "error": error,
            "comment": "host secret key doesn't match any hostpubkey",
        }
    )

    return vectors
