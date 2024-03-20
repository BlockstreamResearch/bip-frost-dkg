# Reference implementation of BIP DKG.
from typing import Tuple, List, Any, Union, Literal, Optional

from secp256k1ref.secp256k1 import Scalar
from secp256k1ref.bip340 import schnorr_sign, schnorr_verify
from secp256k1ref.keys import pubkey_gen_plain
from secp256k1ref.util import tagged_hash, int_from_bytes, bytes_from_int
from network import SignerChannel, CoordinatorChannels

from vss import VSSCommitment, GroupInfo
import simplpedpop
import encpedpop
from util import (
    kdf,
    InvalidBackupError,
    DeserializationError,
    DuplicateHostpubkeyError,
)


def chilldkg_hostkey_gen(seed: bytes) -> Tuple[bytes, bytes]:
    my_hostseckey = kdf(seed, "hostseckey")
    my_hostpubkey = pubkey_gen_plain(my_hostseckey)
    return (my_hostseckey, my_hostpubkey)


SessionParams = Tuple[List[bytes], int, bytes]


def chilldkg_session_params(
    hostpubkeys: List[bytes], t: int, context_string: bytes
) -> Tuple[SessionParams, bytes]:
    if len(hostpubkeys) != len(set(hostpubkeys)):
        raise DuplicateHostpubkeyError

    assert t < 2 ** (4 * 8)
    params_id = tagged_hash(
        "session parameters id",
        b"".join(hostpubkeys) + t.to_bytes(4, byteorder="big") + context_string,
    )
    params = (hostpubkeys, t, params_id)
    return params, params_id


ChillDKGStateR1 = Tuple[SessionParams, int, encpedpop.SignerState1]


def chilldkg_round1(
    seed: bytes, params: SessionParams
) -> Tuple[ChillDKGStateR1, simplpedpop.Unicast1, List[Scalar]]:
    my_hostseckey, my_hostpubkey = chilldkg_hostkey_gen(seed)
    (hostpubkeys, t, params_id) = params
    n = len(hostpubkeys)

    my_idx = hostpubkeys.index(my_hostpubkey)
    enc_state1, (vss_commitment_ext, enc_gen_shares) = encpedpop.signer_round1(
        seed, t, n, my_hostseckey, hostpubkeys, my_idx
    )
    state1 = (params, my_idx, enc_state1)
    return state1, vss_commitment_ext, enc_gen_shares


ChillDKGStateR2 = Tuple[SessionParams, bytes, simplpedpop.DKGOutput]


def chilldkg_round2(
    seed: bytes,
    state1: ChillDKGStateR1,
    vss_commitments_sum: simplpedpop.Broadcast1,
    all_enc_shares_sum: List[Scalar],
) -> Tuple[ChillDKGStateR2, bytes]:
    (my_hostseckey, _) = chilldkg_hostkey_gen(seed)
    (params, my_idx, enc_state1) = state1

    # TODO Not sure if we need to include params_id as eta here. But it won't hurt.
    # Include the enc_shares in eta to ensure that participants agree on all
    # shares, which in turn ensures that they have the right backup.
    # TODO This means all parties who hold the "backup" in the end should
    # participate in Eq?
    my_enc_share = all_enc_shares_sum[my_idx]

    enc_broad1 = encpedpop.Broadcast1(vss_commitments_sum, my_enc_share)
    eta, dkg_output = encpedpop.signer_pre_finalize(enc_state1, enc_broad1)
    eta += b"".join([bytes_from_int(int(share)) for share in all_enc_shares_sum])
    state2 = (params, eta, dkg_output)
    return state2, certifying_eq_round1(my_hostseckey, eta)


def chilldkg_finalize(
    state2: ChillDKGStateR2, cert: bytes
) -> Optional[simplpedpop.DKGOutput]:
    """
    A return value of None means that `cert` is not a valid certificate.

    You MUST NOT delete `state2` in this case.
    The reason is that some other participant may have a valid certificate and thus deem the DKG session successful.
    That other participant will rely on us not having deleted `state2`.
    Once you obtain that valid certificate, you can call `chilldkg_finalize` again with that certificate.
    """
    (params, eta, dkg_output) = state2
    hostpubkeys = params[0]
    if not certifying_eq_finalize(hostpubkeys, eta, cert):
        return None
    return dkg_output


# TODO Make this a subroutine of chilldkg_finalize, which should output the backup.
# The backup must be written to permanent storage before using the dkg_output,
# so it should be coupled with dkg_finalize.
def chilldkg_backup(state2: ChillDKGStateR2, cert: bytes) -> Any:
    eta = state2[1]
    return (eta, cert)


async def chilldkg(
    chan: SignerChannel, seed: bytes, my_hostseckey: bytes, params: SessionParams
) -> Optional[Tuple[simplpedpop.DKGOutput, Any]]:
    # TODO Top-level error handling
    state1, vss_commitment_ext, enc_gen_shares = chilldkg_round1(seed, params)
    chan.send((vss_commitment_ext, enc_gen_shares))
    vss_commitments_sum, all_enc_shares_sum = await chan.receive()

    state2, eq_round1 = chilldkg_round2(
        seed, state1, vss_commitments_sum, all_enc_shares_sum
    )

    chan.send(eq_round1)
    cert = await chan.receive()
    dkg_output = chilldkg_finalize(state2, cert)
    if dkg_output is None:
        return None

    return (dkg_output, chilldkg_backup(state2, cert))


def certifying_eq_round1(my_hostseckey: bytes, x: bytes) -> bytes:
    # TODO: fix aux_rand
    return schnorr_sign(x, my_hostseckey, b"0" * 32)


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


# TODO It's a bit confusing to have this function because it's currently
# only used in the coordinator. Not sure what the best way is to refactor this.
def serialize_eta(
    t: int,
    vss_commit: VSSCommitment,
    hostpubkeys: List[bytes],
    all_enc_shares_sum: List[Scalar],
) -> bytes:
    return (
        t.to_bytes(4, byteorder="big")
        + vss_commit.to_bytes()
        + b"".join(hostpubkeys)
        + b"".join([bytes_from_int(int(share)) for share in all_enc_shares_sum])
    )


async def chilldkg_coordinate(
    chans: CoordinatorChannels, params: SessionParams
) -> Union[GroupInfo, Literal[False]]:
    (hostpubkeys, t, params_id) = params
    n = len(hostpubkeys)
    simpl_round1_ins = []
    all_enc_shares_sum = [Scalar(0)] * n
    for i in range(n):
        simpl_round1_in, enc_shares = await chans.receive_from(i)
        simpl_round1_ins += [simpl_round1_in]
        all_enc_shares_sum = [all_enc_shares_sum[j] + enc_shares[j] for j in range(n)]
    simpl_round1_outs = simplpedpop.coordinator_round1(simpl_round1_ins, t)
    chans.send_all((simpl_round1_outs, all_enc_shares_sum))
    vss_commitment = simplpedpop.assemble_sum_vss_commitment(
        simpl_round1_outs.coms_to_secrets,
        simpl_round1_outs.sum_coms_to_nonconst_terms,
        t,
        n,
    )
    eta = serialize_eta(t, vss_commitment, hostpubkeys, all_enc_shares_sum)
    cert = await certifying_eq_coordinate(chans, hostpubkeys)
    if not verify_cert(hostpubkeys, eta, cert):
        return False
    return vss_commitment.group_info(n)


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

    # Read all_enc_shares_sum (32*n bytes)
    if len(rest) < 32 * n:
        raise DeserializationError
    all_enc_shares_sum, rest = (
        [Scalar(int_from_bytes(rest[i : i + 32])) for i in range(0, 32 * n, 32)],
        rest[32 * n :],
    )

    if len(rest) != 0:
        raise DeserializationError
    return (t, vss_commit, hostpubkeys, all_enc_shares_sum)


# Recovery requires the seed and the public backup
def chilldkg_recover(
    seed: bytes, backup: Any, context_string: bytes
) -> Union[Tuple[simplpedpop.DKGOutput, SessionParams], Literal[False]]:
    (eta, cert) = backup
    try:
        (t, vss_commit, hostpubkeys, all_enc_shares_sum) = deserialize_eta(eta)
    except DeserializationError as e:
        raise InvalidBackupError("Failed to deserialize backup") from e

    n = len(hostpubkeys)
    (params, params_id) = chilldkg_session_params(hostpubkeys, t, context_string)
    my_hostseckey, my_hostpubkey = chilldkg_hostkey_gen(seed)

    # Verify cert
    verify_cert(hostpubkeys, eta, cert)
    # Decrypt share
    enc_context = t.to_bytes(4, byteorder="big") + b"".join(hostpubkeys)

    # Find our hostpubkey
    try:
        my_idx = hostpubkeys.index(my_hostpubkey)
    except ValueError as e:
        raise InvalidBackupError("Seed and backup don't match") from e

    shares_sum = encpedpop.decrypt_sum(
        all_enc_shares_sum[my_idx], my_hostseckey, hostpubkeys, my_idx, enc_context
    )
    # TODO: don't call full round1 function
    (state1, (_, _)) = encpedpop.signer_round1(
        seed, t, len(hostpubkeys), my_hostseckey, hostpubkeys, my_idx
    )
    self_share = state1[4]
    shares_sum += self_share

    # Compute shared & individual pubkeys
    (shared_pubkey, signer_pubkeys) = vss_commit.group_info(n)
    dkg_output = simplpedpop.DKGOutput(shares_sum, shared_pubkey, signer_pubkeys)

    return dkg_output, params
