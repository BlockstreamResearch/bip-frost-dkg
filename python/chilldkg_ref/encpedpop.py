from typing import Tuple, List, NamedTuple

from secp256k1ref.secp256k1 import Scalar
from secp256k1ref.ecdh import ecdh_raw
from secp256k1ref.util import int_from_bytes

from . import simplpedpop
from .util import tagged_hash_bip_dkg, prf, InvalidContributionError


###
### Encryption
###


def ecdh(
    deckey: bytes, my_enckey: bytes, their_enckey: bytes, context: bytes, sending: bool
) -> Scalar:
    data = ecdh_raw(deckey, their_enckey).to_bytes_compressed()
    if sending:
        data += my_enckey + their_enckey
    else:
        data += their_enckey + my_enckey
    assert len(data) == 3 * 33
    data += context
    return Scalar(int_from_bytes(tagged_hash_bip_dkg("encpedpop ecdh", data)))


def encrypt(
    share: Scalar, deckey: bytes, my_enckey: bytes, their_enckey: bytes, context: bytes
) -> Scalar:
    return share + ecdh(deckey, my_enckey, their_enckey, context, sending=True)


def decrypt_sum(
    sum_ciphertexts: Scalar,
    deckey: bytes,
    enckeys: List[bytes],
    idx: int,
    context: bytes,
) -> Scalar:
    secshare = sum_ciphertexts
    for i in range(len(enckeys)):
        if i != idx:
            pad = ecdh(deckey, enckeys[idx], enckeys[i], context, sending=False)
            secshare = secshare - pad
    return secshare


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
    seed_ = prf(seed, "encpedpop seed", enc_context)
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
        if i != participant_idx:  # No need to encrypt to ourselves
            try:
                enc_share = encrypt(
                    shares[i], deckey, enckeys[participant_idx], enckeys[i], enc_context
                )
                enc_shares.append(enc_share)
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
    enc_secshare: Scalar,
) -> Tuple[simplpedpop.DKGOutput, bytes]:
    simpl_state, deckey, enckeys, idx, self_share = state
    simpl_cmsg, = cmsg  # Unpack unary tuple  # fmt: skip

    enc_context = simpl_state.t.to_bytes(4, byteorder="big") + b"".join(enckeys)
    secshare = decrypt_sum(enc_secshare, deckey, enckeys, idx, enc_context)
    secshare += self_share
    dkg_output, eq_input = simplpedpop.participant_step2(
        simpl_state, simpl_cmsg, secshare
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
    for i in range(n):
        # Participant i implicitly uses a pad of 0 to encrypt to themselves.
        # Make this pad explicit at the right position.
        pmsgs[i].enc_shares.insert(i, Scalar(0))
        assert len(pmsgs[i].enc_shares) == n
    enc_secshares = [
        Scalar.sum(*([pmsg.enc_shares[i] for pmsg in pmsgs])) for i in range(n)
    ]
    eq_input += b"".join(enckeys)
    # In ChillDKG, the coordinator needs to broadcast the entire enc_secshares
    # array to all participants. But in pure EncPedPop, the coordinator needs to
    # send to each participant i only their entry enc_secshares[i].
    #
    # Since broadcasting the entire array is not necessary, we don't include it
    # in encpedpop.CoordinatorMsg, but only return it as a side output, so that
    # chilldkg.coordinator_step can pick it up. Implementations of pure
    # EncPedPop will need to decide how to transmit enc_secshares[i] to
    # participant i; we leave this unspecified.
    return CoordinatorMsg(simpl_cmsg), dkg_output, eq_input, enc_secshares
