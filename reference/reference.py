# Reference implementation of BIP DKG.
from typing import Tuple, List, Any, Union, Literal, Optional, NamedTuple

from secp256k1ref.secp256k1 import GE, Scalar
from secp256k1ref.bip340 import schnorr_sign, schnorr_verify
from secp256k1ref.keys import pubkey_gen_plain
from secp256k1ref.util import tagged_hash, int_from_bytes, bytes_from_int

from network import SignerChannel, CoordinatorChannels

from vss import VSS, VSSCommitment, GroupInfo
from util import (
    kdf,
    tagged_hash_bip_dkg,
    BIP_TAG,
    InvalidContributionError,
    InvalidBackupError,
    DeserializationError,
    VSSVerifyError,
    DuplicateHostpubkeyError,
)


Pop = bytes


# An extended VSS Commitment is a VSS commitment with a proof of knowledge
# TODO This should be called SimplPedPopRound1SignerToCoordinator or similar
class VSSCommitmentExt(NamedTuple):
    com: VSSCommitment
    pop: Pop


# A VSS Commitment Sum is the sum of multiple extended VSS Commitments
# TODO This should be called SimplPedPopRound1CoordinatorToSigner or similar
class VSSCommitmentSumExt(NamedTuple):
    first_ges: List[GE]
    remaining_ges: List[GE]
    pops: List[Pop]

    def to_bytes(self) -> bytes:
        return b"".join(
            [
                P.to_bytes_compressed_with_infinity()
                for P in self.first_ges + self.remaining_ges
            ]
        ) + b"".join(self.pops)


# Sum the commitments to the i-th coefficients from the given vss_commitments
# for i > 0. This procedure is introduced by Pedersen in section 5.1 of
# 'Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing'.
def vss_sum_commitments(coms: List[VSSCommitmentExt], t: int) -> VSSCommitmentSumExt:
    first_ges = [com[0].ges[0] for com in coms]
    remaining_ges_sum = [GE.sum(*(com[0].ges[j] for com in coms)) for j in range(1, t)]
    poks = [com[1] for com in coms]
    return VSSCommitmentSumExt(first_ges, remaining_ges_sum, poks)


def vss_commitments_sum_finalize(
    vss_commitments_sum: VSSCommitmentSumExt, t: int, n: int
) -> VSSCommitment:
    # Strip the signatures and sum the commitments to the constant coefficients
    return VSSCommitment(
        [GE.sum(*(vss_commitments_sum.first_ges[i] for i in range(n)))]
        + vss_commitments_sum.remaining_ges
    )


SimplPedPopR1State = Tuple[int, int, int]

POP_MSG_TAG = (BIP_TAG + "VSS PoK").encode()

# To keep the algorithms of SimplPedPop and EncPedPop purely non-interactive computations,
# we omit explicit invocations of an interactive equality check protocol.
# ChillDKG will take care of invoking the equality check protocol.


def simplpedpop_round1(
    seed: bytes, t: int, n: int, my_idx: int
) -> Tuple[SimplPedPopR1State, VSSCommitmentExt, List[Scalar]]:
    """
    Generate SimplPedPop messages to be sent to the coordinator.

    :param bytes seed: FRESH, UNIFORMLY RANDOM 32-byte string
    :param int t: threshold
    :param int n: number of participants
    :param int my_idx: index of this signer in the participant list
    :return: the signer's state, the VSS commitment and the generated shares
    """
    assert t < 2 ** (4 * 8)
    assert my_idx < 2 ** (4 * 8)

    vss = VSS.generate(seed, t)
    shares = vss.shares(n)

    # TODO: fix aux_rand
    sig = schnorr_sign(
        POP_MSG_TAG + my_idx.to_bytes(4, byteorder="big"),
        vss.secret().to_bytes(),
        kdf(seed, "VSS PoK"),
    )

    vss_commitment_ext = VSSCommitmentExt(vss.commit(), sig)
    state = (t, n, my_idx)
    return state, vss_commitment_ext, shares


DKGOutput = Tuple[Scalar, GE, List[GE]]


def simplpedpop_pre_finalize(
    state: SimplPedPopR1State,
    vss_commitments_sum: VSSCommitmentSumExt,
    shares_sum: Scalar,
) -> Tuple[bytes, DKGOutput]:
    """
    Take the messages received from the coordinator and return eta to be compared and DKG output

    :param SimplPedPopR1State state: the signer's state output by simplpedpop_round1
    :param VSSCommitmentSumExt vss_commitments_sum: sum of VSS commitments received from the coordinator
    :param Scalar shares_sum: sum of shares for this participant received from all participants (including this participant)
    :return: the data `eta` that must be input to an equality check protocol, the final share, the shared pubkey, the individual participants' pubkeys
    """
    t, n, my_idx = state
    assert len(vss_commitments_sum.first_ges) == n
    assert len(vss_commitments_sum.remaining_ges) == t - 1
    assert len(vss_commitments_sum.pops) == n

    for i in range(n):
        P_i = vss_commitments_sum.first_ges[i]
        if P_i.infinity:
            raise InvalidContributionError(i, "Participant sent invalid commitment")
        else:
            pk_i = P_i.to_bytes_xonly()
            if not schnorr_verify(
                POP_MSG_TAG + i.to_bytes(4, byteorder="big"),
                pk_i,
                vss_commitments_sum.pops[i],
            ):
                raise InvalidContributionError(
                    i, "Participant sent invalid proof-of-knowledge"
                )
    # Strip the signatures and sum the commitments to the constant coefficients
    vss_commitment = vss_commitments_sum_finalize(vss_commitments_sum, t, n)
    if not vss_commitment.verify(my_idx, shares_sum):
        raise VSSVerifyError()
    eta = t.to_bytes(4, byteorder="big") + vss_commitment.to_bytes()
    shared_pubkey, signer_pubkeys = vss_commitment.group_info(n)
    return eta, (shares_sum, shared_pubkey, signer_pubkeys)


def ecdh(deckey: bytes, enckey: bytes, context: bytes) -> Scalar:
    x = int_from_bytes(deckey)
    assert x != 0
    Y = GE.from_bytes_compressed(enckey)
    Z = x * Y
    assert not Z.infinity
    return Scalar(
        int_from_bytes(tagged_hash_bip_dkg("ECDH", Z.to_bytes_compressed() + context))
    )


def encrypt(share: Scalar, my_deckey: bytes, enckey: bytes, context: bytes) -> Scalar:
    return share + ecdh(my_deckey, enckey, context)


def decrypt_sum(
    ciphertext_sum: Scalar,
    my_deckey: bytes,
    enckeys: List[bytes],
    my_idx: int,
    context: bytes,
) -> Scalar:
    shares_sum = ciphertext_sum
    for i in range(len(enckeys)):
        if i != my_idx:
            shares_sum = shares_sum - ecdh(my_deckey, enckeys[i], context)
    return shares_sum


EncPedPopR1State = Tuple[int, bytes, List[bytes], int, Scalar, SimplPedPopR1State]


def encpedpop_round1(
    seed: bytes, t: int, n: int, my_deckey: bytes, enckeys: List[bytes], my_idx: int
) -> Tuple[EncPedPopR1State, VSSCommitmentExt, List[Scalar]]:
    assert t < 2 ** (4 * 8)
    n = len(enckeys)

    # Protect against reuse of seed in case we previously exported shares
    # encrypted under wrong enckeys.
    enc_context = t.to_bytes(4, byteorder="big") + b"".join(enckeys)
    seed_ = tagged_hash_bip_dkg("EncPedPop seed", seed + enc_context)

    simpl_state, vss_commitment_ext, gen_shares = simplpedpop_round1(
        seed_, t, n, my_idx
    )
    assert len(gen_shares) == n
    enc_gen_shares: List[Scalar] = []
    for i in range(n):
        if i == my_idx:
            # TODO No need to send a constant.
            enc_gen_shares.append(Scalar(0))
        else:
            try:
                enc_gen_shares.append(
                    encrypt(gen_shares[i], my_deckey, enckeys[i], enc_context)
                )
            except ValueError:  # Invalid enckeys[i]
                raise InvalidContributionError(
                    i, "Participant sent invalid encryption key"
                )
    self_share = gen_shares[my_idx]
    state1 = (t, my_deckey, enckeys, my_idx, self_share, simpl_state)
    return state1, vss_commitment_ext, enc_gen_shares


def encpedpop_pre_finalize(
    state1: EncPedPopR1State,
    vss_commitments_sum: VSSCommitmentSumExt,
    enc_shares_sum: Scalar,
) -> Tuple[bytes, DKGOutput]:
    t, my_deckey, enckeys, my_idx, self_share, simpl_state = state1
    n = len(enckeys)

    assert len(vss_commitments_sum.first_ges) == n
    assert len(vss_commitments_sum.remaining_ges) == t - 1
    assert len(vss_commitments_sum.pops) == n

    enc_context = t.to_bytes(4, byteorder="big") + b"".join(enckeys)
    shares_sum = decrypt_sum(enc_shares_sum, my_deckey, enckeys, my_idx, enc_context)
    shares_sum += self_share
    eta, dkg_output = simplpedpop_pre_finalize(
        simpl_state, vss_commitments_sum, shares_sum
    )
    eta += b"".join(enckeys)
    return eta, dkg_output


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


ChillDKGStateR1 = Tuple[SessionParams, int, EncPedPopR1State]


def chilldkg_round1(
    seed: bytes, params: SessionParams
) -> Tuple[ChillDKGStateR1, VSSCommitmentExt, List[Scalar]]:
    my_hostseckey, my_hostpubkey = chilldkg_hostkey_gen(seed)
    (hostpubkeys, t, params_id) = params
    n = len(hostpubkeys)

    my_idx = hostpubkeys.index(my_hostpubkey)
    enc_state1, vss_commitment_ext, enc_gen_shares = encpedpop_round1(
        seed, t, n, my_hostseckey, hostpubkeys, my_idx
    )
    state1 = (params, my_idx, enc_state1)
    return state1, vss_commitment_ext, enc_gen_shares


ChillDKGStateR2 = Tuple[SessionParams, bytes, DKGOutput]


def chilldkg_round2(
    seed: bytes,
    state1: ChillDKGStateR1,
    vss_commitments_sum: VSSCommitmentSumExt,
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

    eta, dkg_output = encpedpop_pre_finalize(
        enc_state1, vss_commitments_sum, my_enc_share
    )
    eta += b"".join([bytes_from_int(int(share)) for share in all_enc_shares_sum])
    state2 = (params, eta, dkg_output)
    return state2, certifying_eq_round1(my_hostseckey, eta)


def chilldkg_finalize(state2: ChillDKGStateR2, cert: bytes) -> Optional[DKGOutput]:
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
) -> Optional[Tuple[DKGOutput, Any]]:
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
    vss_commitments_ext = []
    all_enc_shares_sum = [Scalar(0)] * n
    for i in range(n):
        vss_commitment_ext, enc_shares = await chans.receive_from(i)
        vss_commitments_ext += [vss_commitment_ext]
        all_enc_shares_sum = [all_enc_shares_sum[j] + enc_shares[j] for j in range(n)]
    vss_commitments_sum = vss_sum_commitments(vss_commitments_ext, t)
    chans.send_all((vss_commitments_sum, all_enc_shares_sum))
    eta = serialize_eta(
        t,
        vss_commitments_sum_finalize(vss_commitments_sum, t, n),
        hostpubkeys,
        all_enc_shares_sum,
    )
    cert = await certifying_eq_coordinate(chans, hostpubkeys)
    if not verify_cert(hostpubkeys, eta, cert):
        return False
    vss_commitment = vss_commitments_sum_finalize(vss_commitments_sum, t, n)
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
) -> Union[Tuple[DKGOutput, SessionParams], Literal[False]]:
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

    shares_sum = decrypt_sum(
        all_enc_shares_sum[my_idx], my_hostseckey, hostpubkeys, my_idx, enc_context
    )
    # TODO: don't call full round1 function
    (state1, _, _) = encpedpop_round1(
        seed, t, len(hostpubkeys), my_hostseckey, hostpubkeys, my_idx
    )
    self_share = state1[4]
    shares_sum += self_share

    # Compute shared & individual pubkeys
    (shared_pubkey, signer_pubkeys) = vss_commit.group_info(n)
    dkg_output = (shares_sum, shared_pubkey, signer_pubkeys)

    return dkg_output, params
