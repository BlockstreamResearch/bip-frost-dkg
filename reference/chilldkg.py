# Reference implementation of BIP DKG.
from typing import Tuple, List, Any, Union, Literal, Optional, NamedTuple

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
    InvalidBackupError,
    DeserializationError,
    DuplicateHostpubkeyError,
)


###
### Certifying equality check
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
    params_id: bytes


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


class CoordinatorMsg(NamedTuple):
    enc_cmsg: encpedpop.CoordinatorMsg
    enc_shares_sums: List[Scalar]


# TODO: fix Any type
def deserialize_eta(b: bytes) -> Any:
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
    n, remainder = divmod(len(rest), (33 + 32))
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

    if len(rest) != 0:
        raise DeserializationError
    return (t, sum_vss_commit, hostpubkeys, enc_shares_sums)


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


class Backup(NamedTuple):
    eta: bytes
    cert: bytes


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
    cmsg: CoordinatorMsg,
) -> Tuple[SignerState2, bytes]:
    (hostseckey, _) = hostkey_gen(seed)
    (params, idx, enc_state) = state1
    enc_cmsg, enc_shares_sums = cmsg

    # TODO Not sure if we need to include params_id as eta here. But it won't hurt.
    # Include the enc_shares in eta to ensure that participants agree on all
    # shares, which in turn ensures that they have the right backup.
    # TODO This means all parties who hold the "backup" in the end should
    # participate in Eq?

    dkg_output, eta = encpedpop.signer_pre_finalize(
        enc_state, enc_cmsg, enc_shares_sums[idx]
    )
    eta += b"".join([bytes_from_int(int(share)) for share in enc_shares_sums])
    state2 = SignerState2(params, eta, dkg_output)
    return state2, certifying_eq_signer_step(hostseckey, eta)


def signer_finalize(
    state2: SignerState2, cert: bytes
) -> Optional[Tuple[DKGOutput, Backup]]:
    """A return value of None indicates that the DKG session has not completed
    successfully from our point of view.

    WARNING: Even when obtaining a return value of None, you MUST NOT conclude
    that the DKG session has failed from the point of view of other
    participants, and as a consequence, you MUST NOT erase your seed.

    The underlying reason is that it is possible that some other participant
    deems the DKG session successful, and uses the resulting threshold public
    key (e.g., by sending funds to it.) That other participant can, at any point
    in the future (e.g., when initiating a signing sessions), convince us of the
    success of the DKG session by presenting a public backup that is accepted by
    `signer_recover`."""
    (params, eta, dkg_output) = state2
    if not certifying_eq_verify(params.hostpubkeys, eta, cert):
        return None
    return dkg_output, Backup(eta, cert)


async def signer(
    chan: SignerChannel, seed: bytes, hostseckey: bytes, params: SessionParams
) -> Optional[Tuple[DKGOutput, Backup]]:
    # TODO Top-level error handling
    state1, smsg1 = signer_step1(seed, params)
    chan.send(smsg1)
    cmsg = await chan.receive()

    state2, eq_round1 = signer_step2(seed, state1, cmsg)

    chan.send(eq_round1)
    cert = await chan.receive()

    # TODO: If signer_finalize fails, we should probably not just return None
    # but raise instead. Raising a specific exception is also better for
    # testing.
    return signer_finalize(state2, cert)


# Recovery requires the seed and the public backup
def signer_recover(
    seed: bytes, backup: Backup, context_string: bytes
) -> Union[Tuple[DKGOutput, SessionParams], Literal[False]]:
    (eta, cert) = backup
    try:
        (t, sum_vss_commit, hostpubkeys, enc_shares_sums) = deserialize_eta(eta)
    except DeserializationError as e:
        raise InvalidBackupError("Failed to deserialize backup") from e

    n = len(hostpubkeys)
    (params, params_id) = session_params(hostpubkeys, t, context_string)

    # Verify cert
    certifying_eq_verify(hostpubkeys, eta, cert)

    # Find our hostpubkey
    hostseckey, hostpubkey = hostkey_gen(seed)
    try:
        idx = hostpubkeys.index(hostpubkey)
    except ValueError as e:
        raise InvalidBackupError("Seed and backup don't match") from e

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


def coordinator_step(
    smsgs1: List[SignerMsg1], params: SessionParams
) -> Tuple[CoordinatorMsg, DKGOutput, bytes]:
    enc_cmsg, dkg_output, eta, enc_shares_sums = encpedpop.coordinator_step(
        [smsg1.enc_smsg for smsg1 in smsgs1], params.t, params.hostpubkeys
    )
    eta += b"".join([bytes_from_int(int(share)) for share in enc_shares_sums])
    return CoordinatorMsg(enc_cmsg, enc_shares_sums), dkg_output, eta


async def coordinator(
    chans: CoordinatorChannels, params: SessionParams
) -> Optional[DKGOutput]:
    (hostpubkeys, t, params_id) = params
    n = len(hostpubkeys)
    smsgs1: List[SignerMsg1] = []
    for i in range(n):
        smsgs1.append(await chans.receive_from(i))
    cmsg, dkg_output, eta = coordinator_step(smsgs1, params)
    chans.send_all(cmsg)

    # TODO What to do with this? is this a second coordinator step?
    sigs = []
    for i in range(n):
        sigs += [await chans.receive_from(i)]
    cert = certifying_eq_coordinator_step(sigs)
    chans.send_all(cert)

    # TODO This should probably go to a coordinator_finalize function
    if not certifying_eq_verify(hostpubkeys, eta, cert):
        return None

    return dkg_output
