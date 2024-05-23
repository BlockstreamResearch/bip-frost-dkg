from typing import Tuple, List, NamedTuple

from secp256k1ref.secp256k1 import Scalar
from secp256k1ref.ecdh import ecdh_raw
from secp256k1ref.util import int_from_bytes

import simplpedpop
from util import tagged_hash_bip_dkg, InvalidContributionError


###
### Encryption
###


def ecdh(deckey: bytes, enckey: bytes, context: bytes) -> Scalar:
    shared_secret = ecdh_raw(deckey, enckey)
    return Scalar(
        int_from_bytes(
            tagged_hash_bip_dkg("ECDH", shared_secret.to_bytes_compressed() + context)
        )
    )


def encrypt(share: Scalar, deckey: bytes, enckey: bytes, context: bytes) -> Scalar:
    return share + ecdh(deckey, enckey, context)


def decrypt_sum(
    ciphertext_sum: Scalar,
    deckey: bytes,
    enckeys: List[bytes],
    idx: int,
    context: bytes,
) -> Scalar:
    shares_sum = ciphertext_sum
    for i in range(len(enckeys)):
        if i != idx:
            shares_sum = shares_sum - ecdh(deckey, enckeys[i], context)
    return shares_sum


###
### Messages
###


class ParticipantMsg(NamedTuple):
    simpl_pmsg: simplpedpop.ParticipantMsg
    enc_shares: List[Scalar]


class CoordinatorMsg(NamedTuple):
    simpl_cmsg: simplpedpop.CoordinatorMsg


###
### Participant
###


class ParticipantState(NamedTuple):
    simpl_state: simplpedpop.ParticipantState
    deckey: bytes
    enckeys: List[bytes]
    idx: int
    self_share: Scalar


def session_seed(seed: bytes, enckeys: List[bytes], t: int) -> Tuple[bytes, bytes]:
    enc_context = t.to_bytes(4, byteorder="big") + b"".join(enckeys)
    seed_ = tagged_hash_bip_dkg("EncPedPop seed", seed + enc_context)
    return seed_, enc_context


def participant_step1(
    seed: bytes, t: int, deckey: bytes, enckeys: List[bytes], participant_idx: int
) -> Tuple[ParticipantState, ParticipantMsg]:
    assert t < 2 ** (4 * 8)
    n = len(enckeys)

    # Protect against reuse of seed in case we previously exported shares
    # encrypted under wrong enckeys.
    seed_, enc_context = session_seed(seed, enckeys, t)

    simpl_state, simpl_pmsg, shares = simplpedpop.participant_step1(
        seed_, t, n, participant_idx
    )
    assert len(shares) == n
    enc_shares: List[Scalar] = []
    for i in range(n):
        if i == participant_idx:
            # TODO No need to send a constant.
            enc_shares.append(Scalar(0))
        else:
            try:
                enc_shares.append(encrypt(shares[i], deckey, enckeys[i], enc_context))
            except ValueError:  # Invalid enckeys[i]
                raise InvalidContributionError(
                    i, "Participant sent invalid encryption key"
                )
    self_share = shares[participant_idx]
    pmsg = ParticipantMsg(simpl_pmsg, enc_shares)
    state = ParticipantState(simpl_state, deckey, enckeys, participant_idx, self_share)
    return state, pmsg


def participant_step2(
    state: ParticipantState,
    cmsg: CoordinatorMsg,
    enc_shares_sum: Scalar,
) -> Tuple[simplpedpop.DKGOutput, bytes]:
    simpl_state, deckey, enckeys, idx, self_share = state
    simpl_cmsg, = cmsg  # Unpack unary tuple  # fmt: skip

    enc_context = simpl_state.t.to_bytes(4, byteorder="big") + b"".join(enckeys)
    shares_sum = decrypt_sum(enc_shares_sum, deckey, enckeys, idx, enc_context)
    shares_sum += self_share
    dkg_output, eq_input = simplpedpop.participant_step2(
        simpl_state, simpl_cmsg, shares_sum
    )
    eq_input += b"".join(enckeys)
    return dkg_output, eq_input


###
### Coordinator
###


def coordinator_step(
    pmsgs: List[ParticipantMsg],
    t: int,
    enckeys: List[bytes],
) -> Tuple[CoordinatorMsg, simplpedpop.DKGOutput, bytes, List[Scalar]]:
    n = len(pmsgs)
    simpl_cmsg, dkg_output, eq_input = simplpedpop.coordinator_step(
        [pmsg.simpl_pmsg for pmsg in pmsgs], t, n
    )
    enc_shares_sums = [
        Scalar.sum(*([pmsg.enc_shares[i] for pmsg in pmsgs])) for i in range(n)
    ]
    eq_input += b"".join(enckeys)
    # In pure EncPedPop, the coordinator wants to send enc_shares_sums[i] to each
    # participant i. Broadcasting the entire array to everyone is not necessary, so we
    # don't include it CoordinatorMsg, but only return it as a side output, so that
    # ChillDKG can pick it up.
    # TODO Define a CoordinatorUnicastMsg type to improve this?
    return CoordinatorMsg(simpl_cmsg), dkg_output, eq_input, enc_shares_sums
