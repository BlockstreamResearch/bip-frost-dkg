# Reference implementation of BIP DKG.
from typing import Tuple, List, NamedTuple, NewType

from secp256k1ref.secp256k1 import Scalar
from secp256k1ref.bip340 import schnorr_sign, schnorr_verify
from secp256k1ref.keys import pubkey_gen_plain
from secp256k1ref.util import tagged_hash, int_from_bytes, bytes_from_int
from network import SignerChannel, CoordinatorChannels

from vss import VSS, VSSCommitment
from simplpedpop import DKGOutput, common_dkg_output
import encpedpop
from util import (
    kdf,
    InvalidRecoveryDataError,
    DeserializationError,
    DuplicateHostpubkeyError,
    SessionNotFinalizedError,
)


###
### Certifying equality check
### TODO This is nothing but an aggregate signature scheme
###


def certifying_eq_signer_step(hostseckey: bytes, x: bytes) -> bytes:
    # TODO: fix aux_rand
    return schnorr_sign(x, hostseckey, b"0" * 32)


def certifying_eq_verify(hostpubkeys: List[bytes], x: bytes, cert: bytes) -> bool:
    n = len(hostpubkeys)
    if len(cert) != 64 * n:
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
### Parameters and Setup
###


class SessionParams(NamedTuple):
    hostpubkeys: List[bytes]
    t: int
    params_id: bytes  # TODO This should not be part of the tuple.


def hostkey_gen(seed: bytes) -> Tuple[bytes, bytes]:
    hostseckey = kdf(seed, "hostseckey")
    hostpubkey = pubkey_gen_plain(hostseckey)
    return (hostseckey, hostpubkey)


def session_params(
    hostpubkeys: List[bytes], t: int, context_string: bytes
) -> Tuple[SessionParams, bytes]:
    if len(hostpubkeys) != len(set(hostpubkeys)):
        raise DuplicateHostpubkeyError

    assert t < 2 ** (4 * 8)
    params_id = tagged_hash(
        "session parameters id",
        b"".join(hostpubkeys) + t.to_bytes(4, byteorder="big") + context_string,
    )
    params = SessionParams(hostpubkeys, t, params_id)
    return params, params_id


###
### Messages
###


# TODO These wrappers of single things may be overkill.
class SignerMsg1(NamedTuple):
    enc_smsg: encpedpop.SignerMsg


class SignerMsg2(NamedTuple):
    sig: bytes


class CoordinatorMsg1(NamedTuple):
    enc_cmsg: encpedpop.CoordinatorMsg
    enc_shares_sums: List[Scalar]


class CoordinatorMsg2(NamedTuple):
    cert: bytes


# TODO: fix Any type
def deserialize_recovery_data(
    b: bytes,
) -> Tuple[int, VSSCommitment, List[bytes], List[Scalar], bytes]:
    rest = b

    # Read t (4 bytes)
    if len(rest) < 4:
        raise DeserializationError
    t, rest = int.from_bytes(rest[:4], byteorder="big"), rest[4:]

    # Read sum_vss_commit (33*t bytes)
    if len(rest) < 33 * t:
        raise DeserializationError
    sum_vss_commit, rest = (
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

    # Read enc_shares_sums (32*n bytes)
    if len(rest) < 32 * n:
        raise DeserializationError
    enc_shares_sums, rest = (
        [Scalar(int_from_bytes(rest[i : i + 32])) for i in range(0, 32 * n, 32)],
        rest[32 * n :],
    )

    # Read cert (64*n bytes)
    if len(rest) < 64 * n:
        raise DeserializationError
    cert, rest = rest[: 64 * n], rest[64 * n :]

    if len(rest) != 0:
        raise DeserializationError
    return (t, sum_vss_commit, hostpubkeys, enc_shares_sums, cert)


###
### Signer
###


class SignerState1(NamedTuple):
    params: SessionParams
    signer_idx: int
    enc_state: encpedpop.SignerState


class SignerState2(NamedTuple):
    params: SessionParams
    eta: bytes  # TODO Rename to transcript (TODO (Jonas): maybe transcript is confusing too)
    dkg_output: DKGOutput


RecoveryData = NewType("RecoveryData", bytes)


def signer_step1(seed: bytes, params: SessionParams) -> Tuple[SignerState1, SignerMsg1]:
    hostseckey, hostpubkey = hostkey_gen(seed)
    (hostpubkeys, t, params_id) = params

    signer_idx = hostpubkeys.index(hostpubkey)
    enc_state, enc_smsg = encpedpop.signer_step(
        seed, t, hostseckey, hostpubkeys, signer_idx
    )
    state1 = SignerState1(params, signer_idx, enc_state)
    return state1, SignerMsg1(enc_smsg)


def signer_step2(
    seed: bytes,
    state1: SignerState1,
    cmsg: CoordinatorMsg1,
) -> Tuple[SignerState2, SignerMsg2]:
    (hostseckey, _) = hostkey_gen(seed)
    (params, idx, enc_state) = state1
    enc_cmsg, enc_shares_sums = cmsg

    dkg_output, eta = encpedpop.signer_pre_finalize(
        enc_state, enc_cmsg, enc_shares_sums[idx]
    )
    # TODO Not sure if we need to include params_id in eta here. It contains
    # the context_string, which is currently not included at all!
    # Include the enc_shares in eta to ensure that participants agree on all
    # shares, which in turn ensures that they have the right backup.
    eta += b"".join([bytes_from_int(int(share)) for share in enc_shares_sums])
    state2 = SignerState2(params, eta, dkg_output)
    sig = certifying_eq_signer_step(hostseckey, eta)
    smsg2 = SignerMsg2(sig)
    return state2, smsg2


def signer_finalize(
    state2: SignerState2, cmsg2: CoordinatorMsg2
) -> Tuple[DKGOutput, RecoveryData]:
    """A SessionNotFinalizedError indicates that finalizing the DKG session was
    not successful from our point of view.

    WARNING: Even when obtaining this exception, you MUST NOT conclude that the
    DKG session has failed, and as a consequence, you MUST NOT erase your seed.

    The underlying reason is that it is possible that some other participant
    deems the DKG session successful, and uses the resulting threshold public
    key (e.g., by sending funds to it.) That other participant can, at any point
    in the future (e.g., when initiating a signing sessions), convince us of the
    success of the DKG session by presenting recovery data for which
    `signer_recover` succeeds and produces the expected session parameters."""
    (params, eta, dkg_output) = state2
    if not certifying_eq_verify(params.hostpubkeys, eta, cmsg2.cert):
        raise SessionNotFinalizedError
    return dkg_output, RecoveryData(eta + cmsg2.cert)


async def signer(
    chan: SignerChannel, seed: bytes, hostseckey: bytes, params: SessionParams
) -> Tuple[DKGOutput, RecoveryData]:
    # TODO Top-level error handling
    state1, smsg1 = signer_step1(seed, params)
    chan.send(smsg1)
    cmsg1 = await chan.receive()

    state2, eq_round1 = signer_step2(seed, state1, cmsg1)

    chan.send(eq_round1)
    cmsg2 = await chan.receive()

    return signer_finalize(state2, cmsg2)


# Recovery requires the seed and the public backup
def signer_recover(
    seed: bytes, recovery: RecoveryData, context_string: bytes
) -> Tuple[DKGOutput, SessionParams]:
    try:
        (t, sum_vss_commit, hostpubkeys, enc_shares_sums, cert) = (
            deserialize_recovery_data(recovery)
        )
    except DeserializationError as e:
        raise InvalidRecoveryDataError("Failed to deserialize recovery data") from e

    n = len(hostpubkeys)
    (params, params_id) = session_params(hostpubkeys, t, context_string)

    # Verify cert
    certifying_eq_verify(hostpubkeys, recovery[: 64 * n], cert)

    # Find our hostpubkey
    hostseckey, hostpubkey = hostkey_gen(seed)
    try:
        idx = hostpubkeys.index(hostpubkey)
    except ValueError as e:
        raise InvalidRecoveryDataError("Seed and recovery data don't match") from e

    # Decrypt share
    seed_, enc_context = encpedpop.session_seed(seed, hostpubkeys, t)
    shares_sum = encpedpop.decrypt_sum(
        enc_shares_sums[idx], hostseckey, hostpubkeys, idx, enc_context
    )

    # Derive self_share
    vss = VSS.generate(seed_, t)
    self_share = vss.share_for(idx)
    shares_sum += self_share

    # Compute threshold pubkey and individual pubshares
    (threshold_pubkey, signer_pubshares) = common_dkg_output(sum_vss_commit, n)

    dkg_output = DKGOutput(shares_sum, threshold_pubkey, signer_pubshares)
    return dkg_output, params


###
### Coordinator
###


class CoordinatorState(NamedTuple):
    params: SessionParams
    eta: bytes
    dkg_output: DKGOutput


def coordinator_step(
    smsgs1: List[SignerMsg1], params: SessionParams
) -> Tuple[CoordinatorState, CoordinatorMsg1]:
    enc_cmsg, dkg_output, eta, enc_shares_sums = encpedpop.coordinator_step(
        [smsg1.enc_smsg for smsg1 in smsgs1], params.t, params.hostpubkeys
    )
    eta += b"".join([bytes_from_int(int(share)) for share in enc_shares_sums])
    state = CoordinatorState(params, eta, dkg_output)
    cmsg1 = CoordinatorMsg1(enc_cmsg, enc_shares_sums)
    return state, cmsg1


def coordinator_finalize(
    state: CoordinatorState, smsgs2: List[SignerMsg2]
) -> Tuple[CoordinatorMsg2, DKGOutput, RecoveryData]:
    (params, eta, dkg_output) = state
    cert = certifying_eq_coordinator_step([smsg2.sig for smsg2 in smsgs2])
    if not certifying_eq_verify(params.hostpubkeys, eta, cert):
        raise SessionNotFinalizedError
    return CoordinatorMsg2(cert), dkg_output, RecoveryData(eta + cert)


async def coordinator(
    chans: CoordinatorChannels, params: SessionParams
) -> Tuple[DKGOutput, RecoveryData]:
    (hostpubkeys, t, params_id) = params
    n = len(hostpubkeys)

    smsgs1: List[SignerMsg1] = []
    for i in range(n):
        smsgs1.append(await chans.receive_from(i))
    state, cmsg1 = coordinator_step(smsgs1, params)
    chans.send_all(cmsg1)

    sigs = []
    for i in range(n):
        sigs += [await chans.receive_from(i)]
    cmsg2, dkg_output, recovery_data = coordinator_finalize(state, sigs)
    chans.send_all(cmsg2)

    return dkg_output, recovery_data
