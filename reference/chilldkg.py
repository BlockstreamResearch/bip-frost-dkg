# Reference implementation of BIP DKG.
from typing import Tuple, List, Any, Union, Literal, Optional, NamedTuple

from secp256k1ref.secp256k1 import Scalar
from secp256k1ref.bip340 import schnorr_sign, schnorr_verify
from secp256k1ref.keys import pubkey_gen_plain
from secp256k1ref.util import tagged_hash, int_from_bytes, bytes_from_int
from network import SignerChannel, CoordinatorChannels

from vss import VSSCommitment, GroupInfo
import simplpedpop
from simplpedpop import DKGOutput
import encpedpop
from util import (
    kdf,
    InvalidBackupError,
    DeserializationError,
    DuplicateHostpubkeyError,
)


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


# TODO It's a bit confusing to have this function because it's currently
# only used in the coordinator. The coordinator builds at the transcript only
# at the top-level in chilldkg, but the signers do it layer by layer starting
# from simplpedpop up to encpedpop. We should make that consistent, but it's
# not clear if the one-shot approach or the layered approach makes more sense.
def serialize_eta(
    t: int,
    vss_commit: VSSCommitment,
    hostpubkeys: List[bytes],
    enc_shares_sums: List[Scalar],
) -> bytes:
    return (
        t.to_bytes(4, byteorder="big")
        + vss_commit.to_bytes()
        + b"".join(hostpubkeys)
        + b"".join([bytes_from_int(int(share)) for share in enc_shares_sums])
    )


def deserialize_eta(b: bytes) -> Any:
    rest = b

    # Read t (4 bytes)
    if len(rest) < 4:
        raise DeserializationError
    t, rest = int.from_bytes(rest[:4], byteorder="big"), rest[4:]

    # Read vss_commit (33*t bytes)
    if len(rest) < 33 * t:
        raise DeserializationError
    vss_commit, rest = VSSCommitment.from_bytes_and_t(rest[: 33 * t], t), rest[33 * t :]

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
    return (t, vss_commit, hostpubkeys, enc_shares_sums)


###
### Signer
###


class SignerState1(NamedTuple):
    params: SessionParams
    signer_idx: int
    enc_state: encpedpop.SignerState


class SignerState2(NamedTuple):
    params: SessionParams
    eta: bytes  # TODO Rename to transcript
    dkg_output: DKGOutput


def signer_step1(seed: bytes, params: SessionParams) -> Tuple[SignerState1, SignerMsg1]:
    hostseckey, hostpubkey = hostkey_gen(seed)
    (hostpubkeys, t, params_id) = params
    n = len(hostpubkeys)

    signer_idx = hostpubkeys.index(hostpubkey)
    enc_state, enc_smsg = encpedpop.signer_step(
        seed, t, n, hostseckey, hostpubkeys, signer_idx
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

    eta, dkg_output = encpedpop.signer_pre_finalize(
        enc_state, enc_cmsg, enc_shares_sums[idx]
    )
    eta += b"".join([bytes_from_int(int(share)) for share in enc_shares_sums])
    state2 = SignerState2(params, eta, dkg_output)
    return state2, certifying_eq_round1(hostseckey, eta)


def signer_finalize(state2: SignerState2, cert: bytes) -> Optional[DKGOutput]:
    """
    A return value of None means that `cert` is not a valid certificate.

    You MUST NOT delete `state2` in this case.
    The reason is that some other participant may have a valid certificate and thus deem the DKG session successful.
    That other participant will rely on us not having deleted `state2`.
    Once you obtain that valid certificate, you can call `signer_finalize` again with that certificate.
    """
    (params, eta, dkg_output) = state2
    if not certifying_eq_finalize(params.hostpubkeys, eta, cert):
        return None
    return dkg_output


async def signer(
    chan: SignerChannel, seed: bytes, hostseckey: bytes, params: SessionParams
) -> Optional[Tuple[DKGOutput, Any]]:
    # TODO Top-level error handling
    state1, smsg1 = signer_step1(seed, params)
    chan.send(smsg1)
    cmsg = await chan.receive()

    state2, eq_round1 = signer_step2(seed, state1, cmsg)

    chan.send(eq_round1)
    cert = await chan.receive()
    dkg_output = signer_finalize(state2, cert)
    # TODO We should probably not just return None here but raise instead.
    # Raising a specific exception is also better for testing.
    if dkg_output is None:
        return None

    return (dkg_output, backup(state2, cert))


# TODO Make this a subroutine of signer_finalize, which should output the backup.
# The backup must be written to permanent storage before using the dkg_output,
# so it should be coupled with signer_finalize.
# TODO Fix Any type
def backup(state2: SignerState2, cert: bytes) -> Any:
    eta = state2[1]
    return (eta, cert)


# Recovery requires the seed and the public backup
def signer_recover(
    seed: bytes, backup: Any, context_string: bytes
) -> Union[Tuple[DKGOutput, SessionParams], Literal[False]]:
    (eta, cert) = backup
    try:
        (t, vss_commit, hostpubkeys, enc_shares_sums) = deserialize_eta(eta)
    except DeserializationError as e:
        raise InvalidBackupError("Failed to deserialize backup") from e

    n = len(hostpubkeys)
    (params, params_id) = session_params(hostpubkeys, t, context_string)
    hostseckey, hostpubkey = hostkey_gen(seed)

    # Verify cert
    verify_cert(hostpubkeys, eta, cert)
    # Decrypt share
    enc_context = t.to_bytes(4, byteorder="big") + b"".join(hostpubkeys)

    # Find our hostpubkey
    try:
        idx = hostpubkeys.index(hostpubkey)
    except ValueError as e:
        raise InvalidBackupError("Seed and backup don't match") from e

    shares_sum = encpedpop.decrypt_sum(
        enc_shares_sums[idx], hostseckey, hostpubkeys, idx, enc_context
    )
    # TODO: don't call full round1 function
    (state1, (_, _)) = encpedpop.signer_step(
        seed, t, len(hostpubkeys), hostseckey, hostpubkeys, idx
    )
    self_share = state1[4]
    shares_sum += self_share

    # Compute shared & individual pubkeys
    (shared_pubkey, signer_pubkeys) = vss_commit.group_info(n)
    dkg_output = DKGOutput(shares_sum, shared_pubkey, signer_pubkeys)

    return dkg_output, params


###
### Coordinator
###


def coordinator_step(smsgs1: List[SignerMsg1], t: int) -> CoordinatorMsg:
    enc_cmsg, enc_shares_sums = encpedpop.coordinator_step(
        [smsg1.enc_smsg for smsg1 in smsgs1], t
    )
    return CoordinatorMsg(enc_cmsg, enc_shares_sums)


async def coordinator(
    chans: CoordinatorChannels, params: SessionParams
) -> Union[GroupInfo, Literal[False]]:
    (hostpubkeys, t, params_id) = params
    n = len(hostpubkeys)
    smsgs1: List[SignerMsg1] = []
    for i in range(n):
        smsgs1.append(await chans.receive_from(i))
    cmsg = coordinator_step(smsgs1, t)
    chans.send_all(cmsg)

    # TODO What to do with this? is this a second coordinator step?
    enc_round1_out, enc_shares_sums = cmsg
    vss_commitment = simplpedpop.assemble_sum_vss_commitment(
        enc_round1_out.simpl_cmsg.coms_to_secrets,
        enc_round1_out.simpl_cmsg.sum_coms_to_nonconst_terms,
        t,
        n,
    )
    eta = serialize_eta(t, vss_commitment, hostpubkeys, enc_shares_sums)
    cert = await certifying_eq_coordinate(chans, hostpubkeys)
    if not verify_cert(hostpubkeys, eta, cert):
        return False
    return vss_commitment.group_info(n)


###
### certifying equality check
###


def certifying_eq_round1(hostseckey: bytes, x: bytes) -> bytes:
    # TODO: fix aux_rand
    return schnorr_sign(x, hostseckey, b"0" * 32)


def verify_cert(hostpubkeys: List[bytes], x: bytes, cert: bytes) -> bool:
    n = len(hostpubkeys)
    if len(cert) != 64 * n:
        return False
    is_valid = [
        schnorr_verify(x, hostpubkeys[i][1:33], cert[i * 64 : (i + 1) * 64])
        for i in range(n)
    ]
    return all(is_valid)


def certifying_eq_finalize(hostpubkeys: List[bytes], x: bytes, cert: bytes) -> bool:
    return verify_cert(hostpubkeys, x, cert)


async def certifying_eq_coordinate(
    chans: CoordinatorChannels, hostpubkeys: List[bytes]
) -> bytes:
    n = len(hostpubkeys)
    sigs = []
    for i in range(n):
        sig = await chans.receive_from(i)
        sigs += [sig]
    cert = b"".join(sigs)
    chans.send_all(cert)
    return cert
