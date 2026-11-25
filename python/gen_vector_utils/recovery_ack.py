from secp256k1lab.secp256k1 import Scalar
from secp256k1lab.util import bytes_from_int

from chilldkg_ref import chilldkg

from .fixtures import (
    AUX_RAND_HEX,
    HOSTSECKEYS_HEX,
    RAND_SIG,
    RANDOMS_HEX,
    THRESHOLD_CONFIGS,
)
from .util import (
    INPUT_VALIDATION_DESCRIPTION,
    assign_tc_ids,
    bytes_to_hex,
    expect_exception,
    expect_faulty_exception,
    hex_list_to_bytes,
    params_asdict,
    split_input_validation_cases,
    tg_id,
)


def run_session(t, n):
    # Run a full session and return the host secret keys, the session
    # parameters, and the recovery data.
    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:n])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, t)
    randoms = hex_list_to_bytes(RANDOMS_HEX[:n])
    assert len(randoms) == len(hostpubkeys)
    aux_rand = bytes.fromhex(AUX_RAND_HEX)
    pstates1 = []
    pmsgs1 = []
    for i in range(n):
        state, msg = chilldkg.participant_step1(hostseckeys[i], params, randoms[i])
        pstates1.append(state)
        pmsgs1.append(msg)
    cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)
    pmsgs2 = []
    for i in range(n):
        _, msg = chilldkg.participant_step2(
            hostseckeys[i], pstates1[i], cmsg1, aux_rand
        )
        pmsgs2.append(msg)
    _, _, recovery_data = chilldkg.coordinator_finalize(cstate, pmsgs2)
    return hostseckeys, params, recovery_data


def recovery_data_with_other_cert(hostseckeys, recovery_data):
    # Let the last participant sign the transcript again. The result is
    # recovery data of the same session with a different but valid certificate.
    n = len(hostseckeys)
    eq_input = recovery_data[: -chilldkg.certeq_cert_len(n)]
    sig = chilldkg.certeq_participant_step(
        hostseckeys[n - 1], n - 1, eq_input, b"\x00" * 32
    )
    other_recovery_data = recovery_data[:-64] + sig
    assert other_recovery_data != recovery_data
    chilldkg.coordinator_recover(other_recovery_data)  # Must not raise
    return other_recovery_data


RECOVERY_ACK_SIGN_DESCRIPTION = [
    "Test vectors for participant_recovery_ack_sign(hostseckey, recovery_data, params, aux_rand).",
    "Creates a participant's acknowledgment signature on the transcript contained in the",
    "recovery data.",
    "",
    "A test case may provide 'params', 'recoveryData', and/or 'auxRand' fields to override",
    "the group-level values.",
    "",
    "For each valid test case:",
    "  Call participant_recovery_ack_sign(hostseckey, recoveryData, params, auxRand).",
    "  Verify the returned acknowledgment signature equals expectedAckSig.",
    "",
    "For each error test case:",
    "  Call participant_recovery_ack_sign(hostseckey, recoveryData, params, auxRand).",
    "  Verify it raises an exception matching expectedError.",
    "  Error objects contain 'type' (exception class name) and optionally:",
    "    - 'message': human-readable description (informational, not required to match exactly)",
    *INPUT_VALIDATION_DESCRIPTION,
]


def generate_recovery_ack_sign_group(t, n):
    valid_cases = []
    error_cases = []

    hostseckeys, params, recovery_data = run_session(t, n)
    hostpubkeys = params.hostpubkeys
    aux_rand = bytes.fromhex(AUX_RAND_HEX)

    # --- Valid test case: one per participant index ---
    ack_sigs = []
    for idx in range(n):
        ack_sig = chilldkg.participant_recovery_ack_sign(
            hostseckeys[idx], recovery_data, params, aux_rand
        )
        ack_sigs.append(ack_sig)
        valid_cases.append(
            {
                "hostseckey": bytes_to_hex(hostseckeys[idx]),
                "expectedAckSig": bytes_to_hex(ack_sig),
                "comment": f"valid acknowledgment (idx = {idx})",
            }
        )
    # --- Valid test case: zero auxiliary randomness ---
    zero_aux_rand = b"\x00" * 32
    ack_sig = chilldkg.participant_recovery_ack_sign(
        hostseckeys[0], recovery_data, params, zero_aux_rand
    )
    valid_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "auxRand": bytes_to_hex(zero_aux_rand),
            "expectedAckSig": bytes_to_hex(ack_sig),
            "comment": "valid acknowledgment (auxRand = zero)",
        }
    )
    # --- Valid test case: recovery data with another valid certificate ---
    # The acknowledgment signature covers only the transcript, so it does not
    # depend on the certificate.
    other_recovery_data = recovery_data_with_other_cert(hostseckeys, recovery_data)
    ack_sig = chilldkg.participant_recovery_ack_sign(
        hostseckeys[0], other_recovery_data, params, aux_rand
    )
    assert ack_sig == ack_sigs[0]
    valid_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "recoveryData": bytes_to_hex(other_recovery_data),
            "expectedAckSig": bytes_to_hex(ack_sig),
            "comment": "recovery data with another valid certificate (same acknowledgment as for idx = 0)",
        }
    )

    # --- Error test case: hostseckey doesn't match any hostpubkey ---
    rand_hostseckey = bytes.fromhex(
        "759DE9306FB02B3D84C455112BF1F3360401DC383ECD1FCEDE59EC809D6F9FE7"
    )
    error = expect_exception(
        lambda: chilldkg.participant_recovery_ack_sign(
            rand_hostseckey, recovery_data, params, aux_rand
        ),
        chilldkg.HostSeckeyError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(rand_hostseckey),
            "expectedError": error,
            "comment": "host secret key doesn't match any hostpubkey",
        }
    )
    # --- Error test case: zeroed hostseckey ---
    zeroed_hostseckey = b"\x00" * 32
    error = expect_exception(
        lambda: chilldkg.participant_recovery_ack_sign(
            zeroed_hostseckey, recovery_data, params, aux_rand
        ),
        chilldkg.HostSeckeyError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(zeroed_hostseckey),
            "expectedError": error,
            "comment": "host secret key is zero",
        }
    )
    # --- Error test case: out-of-range hostseckey ---
    overflow_hostseckey = bytes_from_int(Scalar.SIZE)
    error = expect_exception(
        lambda: chilldkg.participant_recovery_ack_sign(
            overflow_hostseckey, recovery_data, params, aux_rand
        ),
        chilldkg.HostSeckeyError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(overflow_hostseckey),
            "expectedError": error,
            "comment": "host secret key is out of range",
        }
    )
    # --- Error test case: threshold doesn't match the recovery data ---
    other_t = t + 1 if t < n else t - 1
    other_params = chilldkg.SessionParams(hostpubkeys, other_t)
    error = expect_exception(
        lambda: chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], recovery_data, other_params, aux_rand
        ),
        chilldkg.RecoveryDataError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(other_params),
            "expectedError": error,
            "comment": "threshold in params doesn't match the recovery data",
        }
    )
    # --- Error test case: hostpubkeys don't match the recovery data ---
    swapped = [hostpubkeys[1], hostpubkeys[0]] + hostpubkeys[2:]
    other_params = chilldkg.SessionParams(swapped, t)
    error = expect_exception(
        lambda: chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], recovery_data, other_params, aux_rand
        ),
        chilldkg.RecoveryDataError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(other_params),
            "expectedError": error,
            "comment": "order of hostpubkeys in params doesn't match the recovery data",
        }
    )
    # --- Error test case: recovery data of invalid length ---
    invalid_recovery_data = recovery_data[1:]
    error = expect_exception(
        lambda: chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], invalid_recovery_data, params, aux_rand
        ),
        chilldkg.RecoveryDataError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "recoveryData": bytes_to_hex(invalid_recovery_data),
            "expectedError": error,
            "comment": "recovery data of invalid length",
        }
    )
    # --- Error test case: last signature in the certificate is invalid ---
    invalid_recovery_data = recovery_data[:-64] + RAND_SIG
    error = expect_exception(
        lambda: chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], invalid_recovery_data, params, aux_rand
        ),
        chilldkg.RecoveryDataError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "recoveryData": bytes_to_hex(invalid_recovery_data),
            "expectedError": error,
            "comment": "last signature in the certificate is invalid",
        }
    )
    # --- Error test case: Wrong hostseckey length ---
    short_hostseckey = bytes.fromhex("631C047D50A67E45E27ED1FF25FCE179")
    assert len(short_hostseckey) == 16
    error = expect_exception(
        lambda: chilldkg.participant_recovery_ack_sign(
            short_hostseckey, recovery_data, params, aux_rand
        ),
        ValueError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(short_hostseckey),
            "expectedError": error,
            "comment": "length of host secret key is not 32 bytes",
        }
    )
    # --- Error test case: Wrong aux randomness length ---
    short_aux_rand = bytes.fromhex("42B53D62E27380D6F7096EDA1C28C57D")
    error = expect_exception(
        lambda: chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], recovery_data, params, short_aux_rand
        ),
        ValueError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "auxRand": bytes_to_hex(short_aux_rand),
            "expectedError": error,
            "comment": "length of aux randomness is not 32 bytes",
        }
    )

    return {
        "tgId": tg_id(t, n),
        "params": params_asdict(params),
        "recoveryData": bytes_to_hex(recovery_data),
        "auxRand": bytes_to_hex(aux_rand),
        "validTestCases": valid_cases,
        "errorTestCases": error_cases,
    }


def generate_recovery_ack_sign_vectors():
    groups = [generate_recovery_ack_sign_group(t, n) for t, n in THRESHOLD_CONFIGS]
    split_input_validation_cases(groups)
    total_tests = assign_tc_ids(groups)
    return {
        "description": RECOVERY_ACK_SIGN_DESCRIPTION,
        "totalTests": total_tests,
        "testGroups": groups,
    }


RECOVERY_ACKS_VERIFY_DESCRIPTION = [
    "Test vectors for participant_recovery_acks_verify(recovery_data, params, ack_sigs).",
    "Verifies the acknowledgment signatures of all participants.",
    "",
    "Assemble the ack_sigs list from ackSigPool using ackSigIndices:",
    "  ack_sigs = [ackSigPool[i] for i in ackSigIndices]",
    "A test case may provide 'params' and/or 'recoveryData' fields to override the",
    "group-level values.",
    "",
    "For each valid test case:",
    "  Call participant_recovery_acks_verify(recoveryData, params, ack_sigs).",
    "  Verify it returns without raising an exception.",
    "",
    "For each error test case:",
    "  Call participant_recovery_acks_verify(recoveryData, params, ack_sigs).",
    "  Verify it raises an exception matching expectedError.",
    "  Error objects contain 'type' (exception class name) and optionally:",
    "    - 'participantId': identifier of the blamed participant",
    "    - 'message': human-readable description (informational, not required to match exactly)",
    *INPUT_VALIDATION_DESCRIPTION,
]


def generate_recovery_acks_verify_group(t, n):
    valid_cases = []
    error_cases = []

    hostseckeys, params, recovery_data = run_session(t, n)
    hostpubkeys = params.hostpubkeys
    aux_rand = bytes.fromhex(AUX_RAND_HEX)

    # build ack_sigs pool with valid signatures at indices [0, 1, ..., n - 1]
    ack_sigs = [
        chilldkg.participant_recovery_ack_sign(
            hostseckeys[i], recovery_data, params, aux_rand
        )
        for i in range(n)
    ]
    ack_sig_pool = [bytes_to_hex(sig) for sig in ack_sigs]
    valid_indices = list(range(n))  # [0, 1, ..., n - 1]

    # --- Valid test case ---
    chilldkg.participant_recovery_acks_verify(recovery_data, params, ack_sigs)
    valid_cases.append(
        {
            "ackSigIndices": valid_indices,
            "comment": "valid acknowledgments",
        }
    )
    # --- Valid test case: recovery data with another valid certificate ---
    # The acknowledgment signatures cover only the transcript, so they are also
    # valid for other recovery data of the same session.
    other_recovery_data = recovery_data_with_other_cert(hostseckeys, recovery_data)
    chilldkg.participant_recovery_acks_verify(other_recovery_data, params, ack_sigs)
    valid_cases.append(
        {
            "recoveryData": bytes_to_hex(other_recovery_data),
            "ackSigIndices": valid_indices,
            "comment": "recovery data with another valid certificate",
        }
    )

    # --- Error test case: invalid signature, one per participant index ---
    ack_sig_pool.append(bytes_to_hex(RAND_SIG))  # index n
    for idx in range(n):
        invalid_ack_sigs = ack_sigs[:idx] + [RAND_SIG] + ack_sigs[idx + 1 :]
        error = expect_faulty_exception(
            lambda: chilldkg.participant_recovery_acks_verify(
                recovery_data, params, invalid_ack_sigs
            ),
            chilldkg.InvalidRecoveryAckError,
            idx,
        )
        error_cases.append(
            {
                "ackSigIndices": [n if i == idx else i for i in range(n)],
                "expectedError": error,
                "comment": f"participant with id {idx} sent an invalid signature",
            }
        )
    # --- Error test case: signatures of participants 0 and 1 are swapped ---
    swapped_ack_sigs = [ack_sigs[1], ack_sigs[0]] + ack_sigs[2:]
    error = expect_faulty_exception(
        lambda: chilldkg.participant_recovery_acks_verify(
            recovery_data, params, swapped_ack_sigs
        ),
        chilldkg.InvalidRecoveryAckError,
        0,
    )
    error_cases.append(
        {
            "ackSigIndices": [1, 0] + valid_indices[2:],
            "expectedError": error,
            "comment": "signatures of participants with ids 0 and 1 are swapped",
        }
    )
    # --- Error test case: CertEq signature instead of an acknowledgment ---
    # The signature of participant 1 in the certificate signs the same
    # transcript but with a different domain separation prefix.
    cert = recovery_data[-chilldkg.certeq_cert_len(n) :]
    certeq_sig = cert[64:128]
    invalid_ack_sigs = [ack_sigs[0], certeq_sig] + ack_sigs[2:]
    error = expect_faulty_exception(
        lambda: chilldkg.participant_recovery_acks_verify(
            recovery_data, params, invalid_ack_sigs
        ),
        chilldkg.InvalidRecoveryAckError,
        1,
    )
    ack_sig_pool.append(bytes_to_hex(certeq_sig))  # index n + 1
    error_cases.append(
        {
            "ackSigIndices": [n + 1 if i == 1 else i for i in range(n)],
            "expectedError": error,
            "comment": "participant with id 1 sent its signature from the certificate",
        }
    )
    # --- Error test case: signature on the full recovery data ---
    # An acknowledgment must sign only the transcript, not the certificate.
    full_sig = chilldkg.recovery_ack_sign(hostseckeys[1], 1, recovery_data, aux_rand)
    invalid_ack_sigs = [ack_sigs[0], full_sig] + ack_sigs[2:]
    error = expect_faulty_exception(
        lambda: chilldkg.participant_recovery_acks_verify(
            recovery_data, params, invalid_ack_sigs
        ),
        chilldkg.InvalidRecoveryAckError,
        1,
    )
    ack_sig_pool.append(bytes_to_hex(full_sig))  # index n + 2
    error_cases.append(
        {
            "ackSigIndices": [n + 2 if i == 1 else i for i in range(n)],
            "expectedError": error,
            "comment": "participant with id 1 signed the full recovery data, including the certificate",
        }
    )
    # --- Error test case: invalid ack_sigs (n-1 entries instead of n) ---
    error = expect_exception(
        lambda: chilldkg.participant_recovery_acks_verify(
            recovery_data, params, ack_sigs[:-1]
        ),
        chilldkg.LengthDoesNotMatchParamsError,
    )
    error_cases.append(
        {
            "ackSigIndices": valid_indices[:-1],  # [0, ..., n - 2]
            "expectedError": error,
            "comment": "invalid ack_sigs: fewer entries than participants",
        }
    )
    # --- Error test case: invalid ack_sigs (n+1 entries instead of n) ---
    error = expect_exception(
        lambda: chilldkg.participant_recovery_acks_verify(
            recovery_data, params, ack_sigs + [ack_sigs[0]]
        ),
        chilldkg.LengthDoesNotMatchParamsError,
    )
    error_cases.append(
        {
            "ackSigIndices": valid_indices + [0],  # [0, 1, ..., n - 1, 0]
            "expectedError": error,
            "comment": "invalid ack_sigs: more entries than participants",
        }
    )
    # --- Error test case: threshold doesn't match the recovery data ---
    other_t = t + 1 if t < n else t - 1
    other_params = chilldkg.SessionParams(hostpubkeys, other_t)
    error = expect_exception(
        lambda: chilldkg.participant_recovery_acks_verify(
            recovery_data, other_params, ack_sigs
        ),
        chilldkg.RecoveryDataError,
    )
    error_cases.append(
        {
            "params": params_asdict(other_params),
            "ackSigIndices": valid_indices,
            "expectedError": error,
            "comment": "threshold in params doesn't match the recovery data",
        }
    )
    # --- Error test case: hostpubkeys don't match the recovery data ---
    swapped = [hostpubkeys[1], hostpubkeys[0]] + hostpubkeys[2:]
    other_params = chilldkg.SessionParams(swapped, t)
    error = expect_exception(
        lambda: chilldkg.participant_recovery_acks_verify(
            recovery_data, other_params, ack_sigs
        ),
        chilldkg.RecoveryDataError,
    )
    error_cases.append(
        {
            "params": params_asdict(other_params),
            "ackSigIndices": valid_indices,
            "expectedError": error,
            "comment": "order of hostpubkeys in params doesn't match the recovery data",
        }
    )
    # --- Error test case: recovery data of invalid length ---
    invalid_recovery_data = recovery_data[1:]
    error = expect_exception(
        lambda: chilldkg.participant_recovery_acks_verify(
            invalid_recovery_data, params, ack_sigs
        ),
        chilldkg.RecoveryDataError,
    )
    error_cases.append(
        {
            "recoveryData": bytes_to_hex(invalid_recovery_data),
            "ackSigIndices": valid_indices,
            "expectedError": error,
            "comment": "recovery data of invalid length",
        }
    )
    # --- Error test case: last signature in the certificate is invalid ---
    invalid_recovery_data = recovery_data[:-64] + RAND_SIG
    error = expect_exception(
        lambda: chilldkg.participant_recovery_acks_verify(
            invalid_recovery_data, params, ack_sigs
        ),
        chilldkg.RecoveryDataError,
    )
    error_cases.append(
        {
            "recoveryData": bytes_to_hex(invalid_recovery_data),
            "ackSigIndices": valid_indices,
            "expectedError": error,
            "comment": "last signature in the certificate is invalid",
        }
    )
    # --- Error test case: participant with id 1 has a short signature ---
    short_sig = ack_sigs[1][:63]
    invalid_ack_sigs = [ack_sigs[0], short_sig] + ack_sigs[2:]
    error = expect_exception(
        lambda: chilldkg.participant_recovery_acks_verify(
            recovery_data, params, invalid_ack_sigs
        ),
        ValueError,
    )
    ack_sig_pool.append(bytes_to_hex(short_sig))  # index n + 3
    error_cases.append(
        {
            "ackSigIndices": [n + 3 if i == 1 else i for i in range(n)],
            "expectedError": error,
            "comment": "participant with id 1 sent a short signature",
        }
    )

    return {
        "tgId": tg_id(t, n),
        "params": params_asdict(params),
        "recoveryData": bytes_to_hex(recovery_data),
        "ackSigPool": ack_sig_pool,
        "validTestCases": valid_cases,
        "errorTestCases": error_cases,
    }


def generate_recovery_acks_verify_vectors():
    groups = [generate_recovery_acks_verify_group(t, n) for t, n in THRESHOLD_CONFIGS]
    split_input_validation_cases(groups)
    total_tests = assign_tc_ids(groups)
    return {
        "description": RECOVERY_ACKS_VERIFY_DESCRIPTION,
        "totalTests": total_tests,
        "testGroups": groups,
    }
