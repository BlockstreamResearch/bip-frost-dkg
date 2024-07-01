"""Reference implementation of ChillDKG.

The public API consists of all functions with docstrings, including the types in
their arguments and return values, and the exceptions they raise). All other
definitions are internal.
"""

from secrets import token_bytes as random_bytes
from typing import Tuple, List, NamedTuple, NewType, Optional

from secp256k1ref.secp256k1 import Scalar
from secp256k1ref.bip340 import schnorr_sign, schnorr_verify
from secp256k1ref.keys import pubkey_gen_plain
from secp256k1ref.util import tagged_hash, int_from_bytes, bytes_from_int

from .vss import VSS, VSSCommitment
from .simplpedpop import DKGOutput, common_dkg_output
from . import encpedpop
from .util import (
    prf,
    InvalidRecoveryDataError,
    DeserializationError,
    DuplicateHostpubkeyError,
    SessionNotFinalizedError,
)

# TODO
# __all__ = []

# TODO Document in all public functions what exceptions they can raise

###
### Certifying equality check
###


def certifying_eq_participant_step(hostseckey: bytes, x: bytes) -> bytes:
    return schnorr_sign(x, hostseckey, aux_rand=random_bytes(32))


def certifying_eq_cert_len(n: int) -> int:
    return 64 * n


def certifying_eq_verify(hostpubkeys: List[bytes], x: bytes, cert: bytes) -> bool:
    n = len(hostpubkeys)
    if len(cert) != certifying_eq_cert_len(n):
        return False
    is_valid = [
        schnorr_verify(x, hostpubkeys[i][1:33], cert[i * 64 : (i + 1) * 64])
        for i in range(n)
    ]
    return all(is_valid)


def certifying_eq_coordinator_step(sigs: List[bytes]) -> bytes:
    cert = b"".join(sigs)
    return cert


###
### Session input and outputs
###


class SessionParams(NamedTuple):
    hostpubkeys: List[bytes]
    t: int


def hostseckey(seed: bytes) -> bytes:
    return prf(seed, "chilldkg hostseckey")


def hostkeypair(seed: bytes) -> Tuple[bytes, bytes]:
    if len(seed) != 32:
        raise ValueError
    seckey = hostseckey(seed)
    pubkey = pubkey_gen_plain(seckey)
    return (seckey, pubkey)


def hostpubkey(seed: bytes) -> bytes:
    """Compute the participant's host public key from the seed.

    This is the long-term cryptographic identity of the participant. It is
    derived deterministically from the secret seed.

    The seed must be 32 bytes of cryptographically secure randomness with
    sufficient entropy to be unpredictable. All outputs of a successful
    participant in a session can be recovered from (a backup of) the seed and
    per-session recovery data.

    The same seed (and thus host public key) can be used in multiple DKG
    sessions. A host public key can be correlated to the threshold public key
    resulting from a DKG session only by parties who observed the session,
    namely the participants, the coordinator (and any eavesdropper).

    :param bytes seed: Participant's long-term secret seed (32 bytes)
    :return: the host public key
    :raises ValueError: if the length of seed is not 32 bytes
    """
    return hostkeypair(seed)[1]


def session_params(hostpubkeys: List[bytes], t: int) -> Tuple[SessionParams, bytes]:
    """Create a SessionParams object along with its params_id.

    A SessionParams object holds the common session parameters of a ChillDKG
    session, namely the list of the host public keys of all participants
    (including the local participants, if applicable) and the participation
    threshold t. All participants and the coordinator in a session must be given
    the same SessionParams object.

    TODO Say something about order and sorting, possibly steal from BIP327.

    Participants must ensure that they have obtained authentic host public keys
    of all the other participants in the session to make sure that they run the
    DKG and generate a threshold public key with the intended set of
    participants. This is analogous to traditional threshold signatures (known
    as "multisig" in the Bitcoin community, see BIP350), where the participants
    need to obtain authentic extended public keys ("xpubs") from the other
    participants to generate multisig addresses, or MuSig2 (see BIP327), where
    the participants need to obtain authentic individual public keys of the
    other participants to generate an aggregated public key.

    In the common scenario that the participants obtain host public keys from
    the other participants over channels that do not provide end-to-end
    authentication of the sending participant (e.g., if the participants simply
    send their unauthenticaed host public keys to the coordinator who is
    supposed to relay them to all participants), the params_id serves as a
    convenient way to perform an out-of-band comparison of all host public keys.
    It is a collision-resistant cryptographic hash of the SessionParams object.
    As a result, if all participants present an identical params_id (as can be
    verified out-of-band), then they all agree on all host public keys and the
    threshold t, and in particular, all participants have obtained authentic
    public host keys.

    :param hostpubkeys List[bytes]: Ordered list of the host public keys of all
        participants
    :param t int: Participation threshold (t participants will be required to sign)
    :return: the SessionParams object and the params_id, a 32-byte string
    :raises ValueError: if 1 <= t <= len(hostpubkeys) does not hold
    :raises OverflowError: if t >= 2^32 (and thus cannot be serialized in 4 bytes)
    """
    if len(hostpubkeys) != len(set(hostpubkeys)):
        raise DuplicateHostpubkeyError
    if not (1 <= t <= len(hostpubkeys)):
        raise ValueError

    params_id = tagged_hash(
        "session parameters id", b"".join(hostpubkeys) + t.to_bytes(4, byteorder="big")
    )
    assert len(params_id) == 32
    params = SessionParams(hostpubkeys, t)
    return params, params_id


RecoveryData = NewType("RecoveryData", bytes)

# TODO What about DKGOutput? It should be here.


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


def deserialize_recovery_data(
    b: bytes,
) -> Tuple[int, VSSCommitment, List[bytes], List[Scalar], bytes]:
    rest = b

    # Read t (4 bytes)
    if len(rest) < 4:
        raise DeserializationError
    t, rest = int.from_bytes(rest[:4], byteorder="big"), rest[4:]

    # Read sum_coms (33*t bytes)
    if len(rest) < 33 * t:
        raise DeserializationError
    sum_coms, rest = (
        VSSCommitment.from_bytes_and_t(rest[: 33 * t], t),
        rest[33 * t :],
    )

    # Compute n
    n, remainder = divmod(len(rest), (33 + 32 + 64))
    if remainder != 0:
        raise DeserializationError

    # Read hostpubkeys (33*n bytes)
    if len(rest) < 33 * n:
        raise DeserializationError
    hostpubkeys, rest = [rest[i : i + 33] for i in range(0, 33 * n, 33)], rest[33 * n :]

    # Read enc_secshares (32*n bytes)
    if len(rest) < 32 * n:
        raise DeserializationError
    enc_secshares, rest = (
        [Scalar(int_from_bytes(rest[i : i + 32])) for i in range(0, 32 * n, 32)],
        rest[32 * n :],
    )

    # Read cert
    cert_len = certifying_eq_cert_len(n)
    if len(rest) < cert_len:
        raise DeserializationError
    cert, rest = rest[:cert_len], rest[cert_len:]

    if len(rest) != 0:
        raise DeserializationError
    return (t, sum_coms, hostpubkeys, enc_secshares, cert)


###
### Participant
###


class ParticipantState1(NamedTuple):
    params: SessionParams
    participant_idx: int
    enc_state: encpedpop.ParticipantState


class ParticipantState2(NamedTuple):
    params: SessionParams
    eq_input: bytes
    dkg_output: DKGOutput


def participant_step1(
    seed: bytes, params: SessionParams
) -> Tuple[ParticipantState1, ParticipantMsg1]:
    """Perform a participant's first step of a ChillDKG session.

    The returned ParticipantState1 should be kept locally, and the returned
    ParticipantMsg1 should be sent to the coordinator.

    :param bytes seed: Participant's long-term secret seed (32 bytes)
    :param SessionParams params: Common session parameters
    :return: the participant's state, and the first message for the coordinator
    :raises ValueError: if the participant's host public key is not in
        params.hostpubkeys
    :raises ValueError: if the length of seed is not 32 bytes
    """
    hostseckey, hostpubkey = hostkeypair(seed)
    (hostpubkeys, t) = params

    participant_idx = hostpubkeys.index(hostpubkey)
    enc_state, enc_pmsg = encpedpop.participant_step1(
        seed, t, hostseckey, hostpubkeys, participant_idx
    )
    state1 = ParticipantState1(params, participant_idx, enc_state)
    return state1, ParticipantMsg1(enc_pmsg)


def participant_step2(
    seed: bytes,
    state1: ParticipantState1,
    cmsg1: CoordinatorMsg1,
) -> Tuple[ParticipantState2, ParticipantMsg2]:
    """Perform a participant's second step of a ChillDKG session.

    The returned ParticipantState2 should be kept locally, and the returned
    ParticipantMsg2 should be sent to the coordinator.

    :param bytes seed: Participant's long-term secret seed (32 bytes)
    :param ParticipantState1 state1: Participant's state after the previous step
    :param cmsg1 CoordinatorMsg1: First message received from the coordinator
    :return: the participant's state, and the second message for the coordinator
    """
    (hostseckey, _) = hostkeypair(seed)
    (params, idx, enc_state) = state1
    enc_cmsg, enc_secshares = cmsg1

    dkg_output, eq_input = encpedpop.participant_step2(
        enc_state, enc_cmsg, enc_secshares[idx]
    )
    # Include the enc_shares in eq_input to ensure that participants agree on all
    # shares, which in turn ensures that they have the right recovery data.
    eq_input += b"".join([bytes_from_int(int(share)) for share in enc_secshares])
    state2 = ParticipantState2(params, eq_input, dkg_output)
    sig = certifying_eq_participant_step(hostseckey, eq_input)
    pmsg2 = ParticipantMsg2(sig)
    return state2, pmsg2


def participant_finalize(
    state2: ParticipantState2, cmsg2: CoordinatorMsg2
) -> Tuple[DKGOutput, RecoveryData]:
    """Perform a participant's final step of a ChillDKG session.

    :param ParticipantState2 state2: Participant's state after the previous step
    :param cmsg2 CoordinatorMsg2: Second message received from the coordinator
    :return: the DKG output and the recovery data
    :raises SessionNotFinalizedError: if finalizing the DKG session was not
        successful from this participant's point of view

    If this functions returns properly (without an exception), then this
    participant deems the DKG session successful. It is, however, possible that
    other participants have received a cmsg2 from the coordinator that made them
    raise a SessionNotFinalizedError instead, or that they have not received a
    cmsg2 from the coordinator at all. These participants can, at any point in
    time in the future (e.g., when initiating a signing session), be convinced
    to deem the session successful by presenting them the recovery data, from
    which they can recover the DKG outputs using the participant_recover
    function.

    .. warning::
       Changing perspectives, this implies that even when obtaining a
       SessionNotFinalizedError, you MUST NOT conclude that the DKG session has
       failed, and as a consequence, you MUST NOT erase the seed. The underlying
       reason is that it is possible that some other participant deems the DKG
       session successful, and uses the resulting threshold public key (e.g., by
       sending funds to it). That other participant can, at any point in the
       future, wish to convince us of the success of the DKG session by
       presenting us recovery data.
    """
    (params, eq_input, dkg_output) = state2
    if not certifying_eq_verify(params.hostpubkeys, eq_input, cmsg2.cert):
        raise SessionNotFinalizedError
    return dkg_output, RecoveryData(eq_input + cmsg2.cert)


###
### Coordinator
###


class CoordinatorState(NamedTuple):
    params: SessionParams
    eq_input: bytes
    dkg_output: DKGOutput


def coordinator_step(
    pmsgs1: List[ParticipantMsg1], params: SessionParams
) -> Tuple[CoordinatorState, CoordinatorMsg1]:
    """Perform the coordinator's first step of a ChillDKG session.

    The returned CoordinatorState should be kept locally, and the returned
    CoordinatorMsg1 should be sent to all participants.

    :param List[ParticipantMsg1] pmsgs1: List of first messages received from
        the participants
    :param SessionParams params: Common session parameters
    :return: the coordinator's state, and the first message for all participants
    """
    enc_cmsg, dkg_output, eq_input, enc_secshares = encpedpop.coordinator_step(
        [pmsg1.enc_pmsg for pmsg1 in pmsgs1], params.t, params.hostpubkeys
    )
    eq_input += b"".join([bytes_from_int(int(share)) for share in enc_secshares])
    state = CoordinatorState(params, eq_input, dkg_output)
    cmsg1 = CoordinatorMsg1(enc_cmsg, enc_secshares)
    return state, cmsg1


def coordinator_finalize(
    state: CoordinatorState, pmsgs2: List[ParticipantMsg2]
) -> Tuple[CoordinatorMsg2, DKGOutput, RecoveryData]:
    """Perform the coordinator's final step of a ChillDKG session.

    The returned CoordinatorMsg2 should be sent to all participants.

    Since the coordinator does not have a secret shares, the DKG output will
    have the secshare field set to None.

    :param CoordinatorState state: Coordinator's state after the previous step
    :param List[ParticipantMsg2] pmsgs2: List of second messages received from
        the participants
    :return: the second message for all participants, the DKG output, and the
        recovry data
    :raises SessionNotFinalizedError: if finalizing the DKG session was not
        successful from the point of view of the coordinator (TODO does it make
        sense to recover the coordinator then?)
    """
    (params, eq_input, dkg_output) = state
    cert = certifying_eq_coordinator_step([pmsg2.sig for pmsg2 in pmsgs2])
    if not certifying_eq_verify(params.hostpubkeys, eq_input, cert):
        raise SessionNotFinalizedError
    return CoordinatorMsg2(cert), dkg_output, RecoveryData(eq_input + cert)


###
### Recovery
###


def recover(
    seed: Optional[bytes], recovery: RecoveryData
) -> Tuple[DKGOutput, SessionParams]:
    """Recover the DKG output of a session from the seed and recovery data.

    This function serves two purposes:
    1. To recover after a SessionNotFinalizedError after obtaining the recovery
       data from another participant or the coordinator (see
       participant_finalize).
    2. To recover from a backup after data loss (e.g., loss of the device).

    :returns: the DKG output and the parameters of the recovered session
    :raises InvalidRecoveryDataError: if recovery failed
    """
    try:
        (t, sum_coms, hostpubkeys, enc_secshares, cert) = deserialize_recovery_data(
            recovery
        )
    except DeserializationError as e:
        raise InvalidRecoveryDataError("Failed to deserialize recovery data") from e

    n = len(hostpubkeys)
    (params, params_id) = session_params(hostpubkeys, t)

    # Verify cert
    certifying_eq_verify(hostpubkeys, recovery[: 64 * n], cert)

    if seed:
        # Find our hostpubkey
        hostseckey, hostpubkey = hostkeypair(seed)
        try:
            idx = hostpubkeys.index(hostpubkey)
        except ValueError as e:
            raise InvalidRecoveryDataError("Seed and recovery data don't match") from e

        # Decrypt share
        seed_, enc_context = encpedpop.session_seed(seed, hostpubkeys, t)
        secshare = encpedpop.decrypt_sum(
            enc_secshares[idx], hostseckey, hostpubkeys, idx, enc_context
        )

        # Derive self_share
        vss = VSS.generate(seed_, t)
        self_share = vss.share_for(idx)
        secshare += self_share
    else:
        secshare = None

    # Compute threshold pubkey and individual pubshares
    (threshold_pubkey, pubshares) = common_dkg_output(sum_coms, n)

    dkg_output = DKGOutput(secshare, threshold_pubkey, pubshares)
    return dkg_output, params
