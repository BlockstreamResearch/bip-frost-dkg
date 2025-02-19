"""Reference implementation of ChillDKG.

WARNING: This code is slow and trivially vulnerable to side channel attacks. Do
not use for anything but tests.

The public API consists of all functions with docstrings, including the types in
their arguments and return values, and the exceptions they raise; see also the
`__all__` list. All other definitions are internal.
"""

from secrets import token_bytes as random_bytes
from typing import Any, Tuple, List, NamedTuple, NewType, Optional, NoReturn, Dict

from secp256k1lab.secp256k1 import Scalar, GE
from secp256k1lab.bip340 import schnorr_sign, schnorr_verify
from secp256k1lab.keys import pubkey_gen_plain
from secp256k1lab.util import bytes_from_int

from .vss import VSSCommitment
from . import encpedpop
from .util import (
    BIP_TAG,
    tagged_hash_bip_dkg,
    ProtocolError,
    FaultyParticipantOrCoordinatorError,
    FaultyCoordinatorError,
    UnknownFaultyParticipantOrCoordinatorError,
    FaultyParticipantError,
)

__all__ = [
    # Functions
    "hostpubkey_gen",
    "params_id",
    "participant_step1",
    "participant_step2",
    "participant_finalize",
    "participant_investigate",
    "coordinator_step1",
    "coordinator_finalize",
    "coordinator_investigate",
    "recover",
    # Exceptions
    "HostSeckeyError",
    "SessionParamsError",
    "InvalidHostPubkeyError",
    "DuplicateHostPubkeyError",
    "ThresholdOrCountError",
    "ProtocolError",
    "FaultyParticipantOrCoordinatorError",
    "FaultyCoordinatorError",
    "UnknownFaultyParticipantOrCoordinatorError",
    "RecoveryDataError",
    # Types
    "SessionParams",
    "DKGOutput",
    "ParticipantMsg1",
    "ParticipantMsg2",
    "CoordinatorInvestigationMsg",
    "ParticipantState1",
    "ParticipantState2",
    "CoordinatorMsg1",
    "CoordinatorMsg2",
    "CoordinatorState",
    "RecoveryData",
]


###
### Equality check protocol CertEq
###


def certeq_message(x: bytes, idx: int) -> bytes:
    # Domain separation as described in BIP 340
    prefix = (BIP_TAG + "certeq message").encode()
    prefix = prefix + b"\x00" * (33 - len(prefix))
    return prefix + idx.to_bytes(4, "big") + x


def certeq_participant_step(hostseckey: bytes, idx: int, x: bytes) -> bytes:
    msg = certeq_message(x, idx)
    return schnorr_sign(msg, hostseckey, aux_rand=random_bytes(32))


def certeq_cert_len(n: int) -> int:
    return 64 * n


def certeq_verify(hostpubkeys: List[bytes], x: bytes, cert: bytes) -> None:
    n = len(hostpubkeys)
    if len(cert) != certeq_cert_len(n):
        raise ValueError
    for i in range(n):
        msg = certeq_message(x, i)
        valid = schnorr_verify(
            msg,
            hostpubkeys[i][1:33],
            cert[i * 64 : (i + 1) * 64],
        )
        if not valid:
            raise InvalidSignatureInCertificateError(i)


def certeq_coordinator_step(sigs: List[bytes]) -> bytes:
    cert = b"".join(sigs)
    return cert


class InvalidSignatureInCertificateError(ValueError):
    def __init__(self, participant: int, *args: Any):
        self.participant = participant
        super().__init__(participant, *args)


###
### Host keys
###


def hostpubkey_gen(hostseckey: bytes) -> bytes:
    """Compute the participant's host public key from the host secret key.

    The host public key is the long-term cryptographic identity of the
    participant.

    This function interprets `hostseckey` as big-endian integer, and computes
    the corresponding "plain" public key in compressed serialization (33 bytes,
    starting with 0x02 or 0x03). This is the key generation procedure
    traditionally used in Bitcoin, e.g., for ECDSA. In other words, this
    function is equivalent to `IndividualPubkey` as defined in
    [[BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#key-generation-of-an-individual-signer)].
    TODO Refer to the FROST signing BIP instead, once that one has a number.

    Arguments:
        hostseckey: This participant's long-term secret key (32 bytes).
            The key **must** be 32 bytes of cryptographically secure randomness
            with sufficient entropy to be unpredictable. All outputs of a
            successful participant in a session can be recovered from (a backup
            of) the key and per-session recovery data.

            The same host secret key (and thus the same host public key) can be
            used in multiple DKG sessions. A host public key can be correlated
            to the threshold public key resulting from a DKG session only by
            parties who observed the session, namely the participants, the
            coordinator (and any eavesdropper).

    Returns:
        The host public key (33 bytes).

    Raises:
        HostSeckeyError: If the length of `hostseckey` is not 32 bytes.
    """
    if len(hostseckey) != 32:
        raise HostSeckeyError

    return pubkey_gen_plain(hostseckey)


class HostSeckeyError(ValueError):
    """Raised if the length of a host secret key is not 32 bytes."""


###
### Session input and outputs
###


# It would be more idiomatic Python to make this a real (data)class, perform
# data validation in the constructor, and add methods to it, but let's stick to
# simple tuples in the public API in order to keep it approachable to readers
# who are not too familiar with Python.
class SessionParams(NamedTuple):
    """A `SessionParams` tuple holds the common parameters of a DKG session.

    Attributes:
        hostpubkeys: Ordered list of the host public keys of all participants.
        t: The participation threshold `t`.
            This is the number of participants that will be required to sign.
            It must hold that `1 <= t <= len(hostpubkeys) <= 2**32 - 1`.

    Participants **must** ensure that they have obtained authentic host
    public keys of all the other participants in the session to make
    sure that they run the DKG and generate a threshold public key with
    the intended set of participants. This is analogous to traditional
    threshold signatures (known as "multisig" in the Bitcoin community),
    [[BIP 383](https://github.com/bitcoin/bips/blob/master/bip-0383.mediawiki)],
    where the participants need to obtain authentic extended public keys
    ("xpubs") from the other participants to generate multisig
    addresses, or MuSig2
    [[BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)],
    where the participants need to obtain authentic individual public
    keys of the other participants to generate an aggregated public key.

    A DKG session will fail if the participants and the coordinator in a session
    don't have the `hostpubkeys` in the same order. This will make sure that
    honest participants agree on the order as part of the session, which is
    useful if the order carries an implicit meaning in the application (e.g., if
    the first `t` participants are the primary participants for signing and the
    others are fallback participants). If there is no canonical order of the
    participants in the application, the caller can sort the list of host public
    keys with the [KeySort algorithm specified in
    BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#key-sorting)
    to abstract away from the order.
    """

    hostpubkeys: List[bytes]
    t: int


def params_validate(params: SessionParams) -> None:
    (hostpubkeys, t) = params

    if not (1 <= t <= len(hostpubkeys) <= 2**32 - 1):
        raise ThresholdOrCountError

    # Check that all hostpubkeys are valid
    for i, hostpubkey in enumerate(hostpubkeys):
        try:
            _ = GE.from_bytes_compressed(hostpubkey)
        except ValueError as e:
            raise InvalidHostPubkeyError(i) from e

    # Check for duplicate hostpubkeys and find the corresponding indices
    hostpubkey_to_idx: Dict[bytes, int] = dict()
    for i, hostpubkey in enumerate(hostpubkeys):
        if hostpubkey in hostpubkey_to_idx:
            raise DuplicateHostPubkeyError(hostpubkey_to_idx[hostpubkey], i)
        hostpubkey_to_idx[hostpubkey] = i


def params_id(params: SessionParams) -> bytes:
    """Return the parameters ID, a unique representation of the `SessionParams`.

    In the common scenario that the participants obtain host public keys from
    the other participants over channels that do not provide end-to-end
    authentication of the sending participant (e.g., if the participants simply
    send their unauthenticated host public keys to the coordinator, who is
    supposed to relay them to all participants), the parameters ID serves as a
    convenient way to perform an out-of-band comparison of all host public keys.
    It is a collision-resistant cryptographic hash of the `SessionParams`
    tuple. As a result, if all participants have obtained an identical
    parameters ID (as can be verified out-of-band), then they all agree on all
    host public keys and the threshold `t`, and in particular, all participants
    have obtained authentic public host keys.

    Returns:
        bytes: The parameters ID, a 32-byte string.

    Raises:
        InvalidHostPubkeyError: If `hostpubkeys` contains an invalid public key.
        DuplicateHostPubkeyError: If `hostpubkeys` contains duplicates.
        ThresholdOrCountError: If `1 <= t <= len(hostpubkeys) <= 2**32 - 1` does
            not hold.
    """
    params_validate(params)
    hostpubkeys, t = params

    t_bytes = t.to_bytes(4, byteorder="big")
    params_id = tagged_hash_bip_dkg(
        "params_id",
        t_bytes + b"".join(hostpubkeys),
    )
    assert len(params_id) == 32
    return params_id


class SessionParamsError(ValueError):
    """Base exception for invalid `SessionParams` tuples."""


class DuplicateHostPubkeyError(SessionParamsError):
    """Raised if two participants have identical host public keys.

    This exception is raised when two participants have an identical host public
    key in the `SessionParams` tuple. Assuming the host public keys in question
    have been transmitted correctly, this exception implies that at least one of
    the two participants is faulty (because duplicates occur only with
    negligible probability if keys are generated honestly).

    Attributes:
        participant1 (int): Index of the first participant.
        participant2 (int): Index of the second participant.
    """

    def __init__(self, participant1: int, participant2: int, *args: Any):
        self.participant1 = participant1
        self.participant2 = participant2
        super().__init__(participant1, participant2, *args)


class InvalidHostPubkeyError(SessionParamsError):
    """Raised if a host public key is invalid.

    This exception is raised when a host public key in the `SessionParams` tuple
    is not a valid public key in compressed serialization. Assuming the host
    public keys in question has been transmitted correctly, this exception
    implies that the corresponding participant is faulty.

    Attributes:
        participant (int): Index of the participant.
    """

    def __init__(self, participant: int, *args: Any):
        self.participant = participant
        super().__init__(participant, *args)


class ThresholdOrCountError(SessionParamsError):
    """Raised if `1 <= t <= len(hostpubkeys) <= 2**32 - 1` does not hold."""


# This is really the same definition as in simplpedpop and encpedpop. We repeat
# it here only to have its docstring in this module.
class DKGOutput(NamedTuple):
    """Holds the outputs of a DKG session.

    Attributes:
        secshare: Secret share of the participant (or `None` for coordinator)
        threshold_pubkey: Generated threshold public key representing the group
        pubshares: Public shares of the participants
    """

    secshare: Optional[bytes]
    threshold_pubkey: bytes
    pubshares: List[bytes]


RecoveryData = NewType("RecoveryData", bytes)


###
### Messages
###


class ParticipantMsg1(NamedTuple):
    enc_pmsg: encpedpop.ParticipantMsg


class ParticipantMsg2(NamedTuple):
    sig: bytes


class CoordinatorMsg1(NamedTuple):
    enc_cmsg: encpedpop.CoordinatorMsg
    enc_secshares: List[Scalar]


class CoordinatorMsg2(NamedTuple):
    cert: bytes


class CoordinatorInvestigationMsg(NamedTuple):
    enc_cinv: encpedpop.CoordinatorInvestigationMsg


def deserialize_recovery_data(
    b: bytes,
) -> Tuple[int, VSSCommitment, List[bytes], List[bytes], List[Scalar], bytes]:
    rest = b

    # Read t (4 bytes)
    if len(rest) < 4:
        raise ValueError
    t, rest = int.from_bytes(rest[:4], byteorder="big"), rest[4:]

    # Read sum_coms (33*t bytes)
    if len(rest) < 33 * t:
        raise ValueError
    sum_coms, rest = (
        VSSCommitment.from_bytes_and_t(rest[: 33 * t], t),
        rest[33 * t :],
    )

    # Compute n
    n, remainder = divmod(len(rest), (33 + 33 + 32 + 64))
    if remainder != 0:
        raise ValueError

    # Read hostpubkeys (33*n bytes)
    if len(rest) < 33 * n:
        raise ValueError
    hostpubkeys, rest = [rest[i : i + 33] for i in range(0, 33 * n, 33)], rest[33 * n :]

    # Read pubnonces (33*n bytes)
    if len(rest) < 33 * n:
        raise ValueError
    pubnonces, rest = [rest[i : i + 33] for i in range(0, 33 * n, 33)], rest[33 * n :]

    # Read enc_secshares (32*n bytes)
    if len(rest) < 32 * n:
        raise ValueError
    enc_secshares, rest = (
        [Scalar.from_bytes(rest[i : i + 32]) for i in range(0, 32 * n, 32)],
        rest[32 * n :],
    )

    # Read cert
    cert_len = certeq_cert_len(n)
    if len(rest) < cert_len:
        raise ValueError
    cert, rest = rest[:cert_len], rest[cert_len:]

    if len(rest) != 0:
        raise ValueError
    return (t, sum_coms, hostpubkeys, pubnonces, enc_secshares, cert)


###
### Participant
###


class ParticipantState1(NamedTuple):
    params: SessionParams
    idx: int
    enc_state: encpedpop.ParticipantState


class ParticipantState2(NamedTuple):
    params: SessionParams
    eq_input: bytes
    dkg_output: DKGOutput


def participant_step1(
    hostseckey: bytes, params: SessionParams, random: bytes
) -> Tuple[ParticipantState1, ParticipantMsg1]:
    """Perform a participant's first step of a ChillDKG session.

    Arguments:
        hostseckey: Participant's long-term host secret key (32 bytes).
        params: Common session parameters.
        random: FRESH random byte string (32 bytes).

    Returns:
        ParticipantState1: The participant's session state after this step, to
            be passed as an argument to `participant_step2`. The state **must
            not** be reused (i.e., it must be passed only to one
            `participant_step2` call).
        ParticipantMsg1: The first message to be sent to the coordinator.

    Raises:
        HostSeckeyError: If the length of `hostseckey` is not 32 bytes or if
            `hostseckey` does not match any entry of `hostpubkeys`.
        InvalidHostPubkeyError: If `hostpubkeys` contains an invalid public key.
        DuplicateHostPubkeyError: If `hostpubkeys` contains duplicates.
        ThresholdOrCountError: If `1 <= t <= len(hostpubkeys) <= 2**32 - 1` does
            not hold.
    """
    hostpubkey = hostpubkey_gen(hostseckey)  # HostSeckeyError if len(hostseckey) != 32

    params_validate(params)
    (hostpubkeys, t) = params

    try:
        idx = hostpubkeys.index(hostpubkey)
    except ValueError as e:
        raise HostSeckeyError(
            "Host secret key does not match any host public key"
        ) from e
    enc_state, enc_pmsg = encpedpop.participant_step1(
        # We know that EncPedPop uses its seed only by feeding it to a hash
        # function. Thus, it is sufficient that the seed has a high entropy,
        # and so we can simply pass the hostseckey as seed.
        seed=hostseckey,
        deckey=hostseckey,
        t=t,
        # This requires the joint security of Schnorr signatures and ECDH.
        enckeys=hostpubkeys,
        idx=idx,
        random=random,
    )  # HostSeckeyError if len(hostseckey) != 32
    state1 = ParticipantState1(params, idx, enc_state)
    return state1, ParticipantMsg1(enc_pmsg)


def participant_step2(
    hostseckey: bytes,
    state1: ParticipantState1,
    cmsg1: CoordinatorMsg1,
) -> Tuple[ParticipantState2, ParticipantMsg2]:
    """Perform a participant's second step of a ChillDKG session.

    **Warning:**
    After sending the returned message to the coordinator, this participant
    **must not** erase the hostseckey, even if this participant does not receive
    the coordinator reply needed for the `participant_finalize` call. The
    underlying reason is that some other participant may receive the coordinator
    reply, deem the DKG session successful and use the resulting threshold
    public key (e.g., by sending funds to it). If the coordinator reply remains
    missing, that other participant can, at any point in the future, convince
    this participant of the success of the DKG session by presenting recovery
    data, from which this participant can recover the DKG output using the
    `recover` function.

    Arguments:
        hostseckey: Participant's long-term host secret key (32 bytes).
        state1: The participant's session state as output by
            `participant_step1`.
        cmsg1: The first message received from the coordinator.

    Returns:
        ParticipantState2: The participant's session state after this step, to
            be passed as an argument to `participant_finalize`. The state **must
            not** be reused (i.e., it must be passed only to one
            `participant_finalize` call).
        ParticipantMsg2: The second message to be sent to the coordinator.

    Raises:
        HostSeckeyError: If the length of `hostseckey` is not 32 bytes.
        FaultyParticipantOrCoordinatorError: If another known participant or the
            coordinator is faulty. See the documentation of the exception for
            further details.
        UnknownFaultyParticipantOrCoordinatorError: If another unknown
            participant or the coordinator is faulty, but running the optional
            investigation procedure of the protocol is necessary to determine a
            suspected participant. See the documentation of the exception for
            further details.
    """
    params, idx, enc_state = state1
    enc_cmsg, enc_secshares = cmsg1

    enc_dkg_output, eq_input = encpedpop.participant_step2(
        state=enc_state,
        deckey=hostseckey,
        cmsg=enc_cmsg,
        enc_secshare=enc_secshares[idx],
    )

    # Include the enc_shares in eq_input to ensure that participants agree on
    # all shares, which in turn ensures that they have the right recovery data.
    eq_input += b"".join([bytes_from_int(int(share)) for share in enc_secshares])
    dkg_output = DKGOutput._make(enc_dkg_output)
    state2 = ParticipantState2(params, eq_input, dkg_output)
    sig = certeq_participant_step(hostseckey, idx, eq_input)
    pmsg2 = ParticipantMsg2(sig)
    return state2, pmsg2


def participant_finalize(
    state2: ParticipantState2, cmsg2: CoordinatorMsg2
) -> Tuple[DKGOutput, RecoveryData]:
    """Perform a participant's final step of a ChillDKG session.

    If this function returns properly (without an exception), then this
    participant deems the DKG session successful. It is, however, possible that
    other participants have received a `cmsg2` from the coordinator that made
    them raise an exception instead, or that they have not received a `cmsg2`
    from the coordinator at all. These participants can, at any point in time in
    the future (e.g., when initiating a signing session), be convinced to deem
    the session successful by presenting the recovery data to them, from which
    they can recover the DKG outputs using the `recover` function.

    **Warning:**
    Changing perspectives, this implies that, even when obtaining an exception,
    this participant **must not** conclude that the DKG session has failed, and
    as a consequence, this particiant **must not** erase the hostseckey. The
    underlying reason is that some other participant may deem the DKG session
    successful and use the resulting threshold public key (e.g., by sending
    funds to it). That other participant can, at any point in the future,
    convince this participant of the success of the DKG session by presenting
    recovery data to this participant.

    Arguments:
        state2: The participant's state as output by `participant_step2`.

    Returns:
        DKGOutput: The DKG output.
        bytes: The serialized recovery data.

    Raises:
        FaultyParticipantOrCoordinatorError: If another known participant or the
            coordinator is faulty. Make sure to read the above warning, and see
            the documentation of the exception for further details.
        FaultyCoordinatorError: If the coordinator is faulty. Make sure to read
            the above warning, and see the documentation of the exception for
            further details.
    """
    params, eq_input, dkg_output = state2
    try:
        certeq_verify(params.hostpubkeys, eq_input, cmsg2.cert)
    except InvalidSignatureInCertificateError as e:
        raise FaultyParticipantOrCoordinatorError(
            e.participant,
            "Participant has provided an invalid signature for the certificate",
        ) from e
    return dkg_output, RecoveryData(eq_input + cmsg2.cert)


def participant_investigate(
    error: UnknownFaultyParticipantOrCoordinatorError,
    cinv: CoordinatorInvestigationMsg,
) -> NoReturn:
    """Investigate who is to blame for a failed ChillDKG session.

    This function can optionally be called when `participant_step2` raises
    `UnknownFaultyParticipantOrCoordinatorError`. It narrows down the suspected
    faulty parties by analyzing the investigation message provided by the coordinator.

    This function does not return normally. Instead, it raises one of two
    exceptions.

    Arguments:
        error: `UnknownFaultyParticipantOrCoordinatorError` raised by
            `participant_step2`.
        cinv: Coordinator investigation message for this participant as output
            by `coordinator_investigate`.

    Raises:
        FaultyParticipantOrCoordinatorError: If another known participant or the
            coordinator is faulty. See the documentation of the exception for
            further details.
        FaultyCoordinatorError: If the coordinator is faulty. See the
            documentation of the exception for further details.
    """
    assert isinstance(error.inv_data, encpedpop.ParticipantInvestigationData)
    encpedpop.participant_investigate(
        error=error,
        cinv=cinv.enc_cinv,
    )


###
### Coordinator
###


class CoordinatorState(NamedTuple):
    params: SessionParams
    eq_input: bytes
    dkg_output: DKGOutput


def coordinator_step1(
    pmsgs1: List[ParticipantMsg1], params: SessionParams
) -> Tuple[CoordinatorState, CoordinatorMsg1]:
    """Perform the coordinator's first step of a ChillDKG session.

    Arguments:
        pmsgs1: List of first messages received from the participants.
        params: Common session parameters.

    Returns:
        CoordinatorState: The coordinator's session state after this step, to be
            passed as an argument to `coordinator_finalize`. The state is not
            supposed to be reused (i.e., it should be passed only to one
            `coordinator_finalize` call).
        CoordinatorMsg1: The first message to be sent to all participants.

    Raises:
        InvalidHostPubkeyError: If `hostpubkeys` contains an invalid public key.
        DuplicateHostPubkeyError: If `hostpubkeys` contains duplicates.
        ThresholdOrCountError: If `1 <= t <= len(hostpubkeys) <= 2**32 - 1` does
            not hold.
    """
    params_validate(params)
    hostpubkeys, t = params

    enc_cmsg, enc_dkg_output, eq_input, enc_secshares = encpedpop.coordinator_step(
        pmsgs=[pmsg1.enc_pmsg for pmsg1 in pmsgs1],
        t=t,
        enckeys=hostpubkeys,
    )
    eq_input += b"".join([bytes_from_int(int(share)) for share in enc_secshares])
    dkg_output = DKGOutput._make(enc_dkg_output)  # Convert to chilldkg.DKGOutput type
    state = CoordinatorState(params, eq_input, dkg_output)
    cmsg1 = CoordinatorMsg1(enc_cmsg, enc_secshares)
    return state, cmsg1


def coordinator_finalize(
    state: CoordinatorState, pmsgs2: List[ParticipantMsg2]
) -> Tuple[CoordinatorMsg2, DKGOutput, RecoveryData]:
    """Perform the coordinator's final step of a ChillDKG session.

    If this function returns properly (without an exception), then the
    coordinator deems the DKG session successful. The returned `CoordinatorMsg2`
    is supposed to be sent to all participants, who are supposed to pass it as
    input to the `participant_finalize` function. It is, however, possible that
    some participants pass a wrong and invalid message to `participant_finalize`
    (e.g., because the message is transmitted incorrectly). These participants
    can, at any point in time in the future (e.g., when initiating a signing
    session), be convinced to deem the session successful by presenting the
    recovery data to them, from which they can recover the DKG outputs using the
    `recover` function.

    If this function raises an exception, then the DKG session was not
    successful from the perspective of the coordinator. In this case, it is, in
    principle, possible to recover the DKG outputs of the coordinator using the
    recovery data from a successful participant, should one exist. Any such
    successful participant is either faulty, or has received messages from
    other participants via a communication channel beside the coordinator.

    Arguments:
        state: The coordinator's session state as output by `coordinator_step1`.
        pmsgs2: List of second messages received from the participants.

    Returns:
        CoordinatorMsg2: The second message to be sent to all participants.
        DKGOutput: The DKG output. Since the coordinator does not have a secret
            share, the DKG output will have the `secshare` field set to `None`.
        bytes: The serialized recovery data.

    Raises:
        FaultyParticipantError: If another known participant or the coordinator
            is faulty. See the documentation of the exception for further
            details.
    """
    params, eq_input, dkg_output = state
    cert = certeq_coordinator_step([pmsg2.sig for pmsg2 in pmsgs2])
    try:
        certeq_verify(params.hostpubkeys, eq_input, cert)
    except InvalidSignatureInCertificateError as e:
        raise FaultyParticipantError(
            e.participant,
            "Participant has provided an invalid signature for the certificate",
        ) from e
    return CoordinatorMsg2(cert), dkg_output, RecoveryData(eq_input + cert)


def coordinator_investigate(
    pmsgs: List[ParticipantMsg1],
) -> List[CoordinatorInvestigationMsg]:
    """Generate investigation messages for a ChillDKG session.

    The investigation messages will allow the participants to investigate who is
    to blame for a failed ChillDKG session (see `participant_investigate`).

    Each message is intended for a single participant but can be safely
    broadcast to all participants because the messages contain no confidential
    information.

    Arguments:
        pmsgs: List of first messages received from the participants.

    Returns:
        List[CoordinatorInvestigationMsg]: A list of investigation messages, each
            intended for a single participant.
    """
    enc_cinvs = encpedpop.coordinator_investigate([pmsg.enc_pmsg for pmsg in pmsgs])
    return [CoordinatorInvestigationMsg(enc_cinv) for enc_cinv in enc_cinvs]


###
### Recovery
###


def recover(
    hostseckey: Optional[bytes], recovery_data: RecoveryData
) -> Tuple[DKGOutput, SessionParams]:
    """Recover the DKG output of a ChillDKG session.

    This function serves two different purposes:
    1. To recover from an exception in `participant_finalize` or
       `coordinator_finalize`, after obtaining the recovery data from another
        participant or the coordinator. See `participant_finalize` and
        `coordinator_finalize` for background.
    2. To reproduce the DKG outputs on a new device, e.g., to recover from a
       backup after data loss.

    Arguments:
        hostseckey: This participant's long-term host secret key (32 bytes) or
            `None` if recovering the coordinator.
        recovery_data: Recovery data from a successful session.

    Returns:
        DKGOutput: The recovered DKG output.
        SessionParams: The common parameters of the recovered session.

    Raises:
        HostSeckeyError: If the length of `hostseckey` is not 32 bytes or if
            `hostseckey` does not match the recovery data. (This can also
            occur if the recovery data is invalid.)
        RecoveryDataError: If recovery failed due to invalid recovery data.
    """
    try:
        (t, sum_coms, hostpubkeys, pubnonces, enc_secshares, cert) = (
            deserialize_recovery_data(recovery_data)
        )
    except Exception as e:
        raise RecoveryDataError("Failed to deserialize recovery data") from e

    n = len(hostpubkeys)
    params = SessionParams(hostpubkeys, t)
    try:
        params_validate(params)
    except SessionParamsError as e:
        raise RecoveryDataError("Invalid session parameters in recovery data") from e

    # Verify cert
    eq_input = recovery_data[: -len(cert)]
    try:
        certeq_verify(hostpubkeys, eq_input, cert)
    except InvalidSignatureInCertificateError as e:
        raise RecoveryDataError("Invalid certificate in recovery data") from e

    # Compute threshold pubkey and individual pubshares
    sum_coms, tweak, _ = sum_coms.invalid_taproot_commit()
    threshold_pubkey = sum_coms.commitment_to_secret()
    pubshares = [sum_coms.pubshare(i) for i in range(n)]

    if hostseckey:
        hostpubkey = hostpubkey_gen(hostseckey)  # HostSeckeyError
        try:
            idx = hostpubkeys.index(hostpubkey)
        except ValueError as e:
            raise HostSeckeyError(
                "Host secret key does not match any host public key in the recovery data"
            ) from e

        # Decrypt share
        enc_context = encpedpop.serialize_enc_context(t, hostpubkeys)
        secshare = encpedpop.decrypt_sum(
            hostseckey,
            hostpubkeys[idx],
            pubnonces,
            enc_context,
            idx,
            enc_secshares[idx],
        )
        secshare_tweaked = secshare + tweak

        # This is just a sanity check. Our signature is valid, so we have done
        # an equivalent check already during the actual session.
        assert VSSCommitment.verify_secshare(secshare_tweaked, pubshares[idx])
    else:
        secshare_tweaked = None

    dkg_output = DKGOutput(
        None if secshare_tweaked is None else secshare_tweaked.to_bytes(),
        threshold_pubkey.to_bytes_compressed(),
        [pubshare.to_bytes_compressed() for pubshare in pubshares],
    )
    return dkg_output, params


class RecoveryDataError(ValueError):
    """Raised if the recovery data is invalid."""
