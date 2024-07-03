from typing import Tuple, List, NamedTuple

from secp256k1ref.secp256k1 import Scalar
from secp256k1ref.ecdh import ecdh_libsecp256k1
from secp256k1ref.keys import pubkey_gen_plain
from secp256k1ref.util import int_from_bytes

from . import simplpedpop
from .util import tagged_hash_bip_dkg, prf, InvalidContributionError


###
### Encryption
###


def ecdh(
    seckey: bytes, my_pubkey: bytes, their_pubkey: bytes, context: bytes, sending: bool
) -> Scalar:
    # TODO Decide on exact ecdh variant to use
    data = ecdh_libsecp256k1(seckey, their_pubkey)
    if sending:
        data += my_pubkey + their_pubkey
    else:
        data += their_pubkey + my_pubkey
    assert len(data) == 2 * 33 + 32
    data += context
    return Scalar(int_from_bytes(tagged_hash_bip_dkg("encpedpop ecdh", data)))


def encrypt_multi(
    secnonce: bytes,
    pubnonce: bytes,
    enckeys: List[bytes],
    messages: List[Scalar],
    context: bytes,
) -> List[Scalar]:
    ciphertexts = [
        message + ecdh(secnonce, pubnonce, enckey, context, sending=True)
        for message, enckey in zip(messages, enckeys, strict=True)
    ]
    return ciphertexts


def decrypt_sum(
    deckey: bytes,
    pubkey: bytes,
    pubnonces: List[bytes],
    sum_ciphertexts: Scalar,
    context: bytes,
) -> Scalar:
    secshare = sum_ciphertexts
    for pubnonce in pubnonces:
        pad = ecdh(deckey, pubkey, pubnonce, context, sending=False)
        secshare = secshare - pad
    return secshare


###
### Messages
###


class ParticipantMsg(NamedTuple):
    simpl_pmsg: simplpedpop.ParticipantMsg
    pubnonce: bytes
    enc_shares: List[Scalar]


class CoordinatorMsg(NamedTuple):
    simpl_cmsg: simplpedpop.CoordinatorMsg
    pubnonces: List[bytes]


###
### Participant
###


class ParticipantState(NamedTuple):
    simpl_state: simplpedpop.ParticipantState
    pubnonce: bytes
    enckeys: List[bytes]
    idx: int
    my_share: Scalar


def serialize_enc_context(t, enckeys):
    return t.to_bytes(4, byteorder="big") + b"".join(enckeys)


def derive_session_seed(seed: bytes, pubnonce: bytes, enc_context: bytes) -> bytes:
    return prf(seed, "encpedpop seed", pubnonce + enc_context)


def participant_step1(
    seed: bytes,
    t: int,
    enckeys: List[bytes],
    participant_idx: int,
    random: bytes,
) -> Tuple[ParticipantState, ParticipantMsg]:
    assert t < 2 ** (4 * 8)
    assert len(random) == 32
    n = len(enckeys)

    # Create a synthetic encryption nonce
    enc_context = serialize_enc_context(t, enckeys)
    secnonce = prf(seed, "encpodpop secnonce", random + enc_context)
    # This can be optimized: We serialize the pubnonce here, but ecdh will need
    # to deserialize it again, which involves computing a square root to obtain
    # the y coordinate.
    pubnonce = pubkey_gen_plain(secnonce)
    # Add enc_context again to the derivation of the session seed, just in case
    # someone derives secnonce differently.
    session_seed = derive_session_seed(seed, pubnonce, enc_context)

    simpl_state, simpl_pmsg, shares = simplpedpop.participant_step1(
        session_seed, t, n, participant_idx
    )
    assert len(shares) == n

    # Encrypt shares, no need to encrypt to ourselves
    their_shares = shares.copy()
    my_share = their_shares.pop(participant_idx)
    their_enckeys = enckeys.copy()
    _ = their_enckeys.pop(participant_idx)
    enc_shares = encrypt_multi(
        secnonce, pubnonce, their_enckeys, their_shares, enc_context
    )

    pmsg = ParticipantMsg(simpl_pmsg, pubnonce, enc_shares)
    state = ParticipantState(simpl_state, pubnonce, enckeys, participant_idx, my_share)
    return state, pmsg


def participant_step2(
    state: ParticipantState,
    deckey: bytes,
    cmsg: CoordinatorMsg,
    enc_secshare: Scalar,
) -> Tuple[simplpedpop.DKGOutput, bytes]:
    simpl_state, pubnonce, enckeys, idx, self_share = state
    simpl_cmsg, pubnonces = cmsg

    their_pubnonces = pubnonces.copy()
    reported_pubnonce = their_pubnonces.pop(idx)
    if reported_pubnonce != pubnonce:
        raise InvalidContributionError(None, "Coordinator replied with wrong pubnonce")

    enc_context = serialize_enc_context(simpl_state.t, enckeys)
    secshare = decrypt_sum(
        deckey, enckeys[idx], their_pubnonces, enc_secshare, enc_context
    )
    secshare += self_share
    dkg_output, eq_input = simplpedpop.participant_step2(
        simpl_state, simpl_cmsg, secshare
    )
    eq_input += b"".join(enckeys) + b"".join(pubnonces)
    return dkg_output, eq_input


###
### Coordinator
###


def coordinator_step(
    pmsgs: List[ParticipantMsg],
    t: int,
    enckeys: List[bytes],
) -> Tuple[CoordinatorMsg, simplpedpop.DKGOutput, bytes, List[Scalar]]:
    n = len(enckeys)
    if n != len(pmsgs):
        raise ValueError
    simpl_cmsg, dkg_output, eq_input = simplpedpop.coordinator_step(
        [pmsg.simpl_pmsg for pmsg in pmsgs], t, n
    )
    pubnonces = [pmsg.pubnonce for pmsg in pmsgs]
    for i in range(n):
        # Participant i implicitly uses a pad of 0 to encrypt to themselves.
        # Make this pad explicit at the right position.
        if len(pmsgs[i].enc_shares) != n - 1:
            raise InvalidContributionError(
                i, "Participant sent enc_shares with invalid length"
            )
        pmsgs[i].enc_shares.insert(i, Scalar(0))
    enc_secshares = [
        Scalar.sum(*([pmsg.enc_shares[i] for pmsg in pmsgs])) for i in range(n)
    ]
    eq_input += b"".join(enckeys) + b"".join(pubnonces)
    # In ChillDKG, the coordinator needs to broadcast the entire enc_secshares
    # array to all participants. But in pure EncPedPop, the coordinator needs to
    # send to each participant i only their entry enc_secshares[i].
    #
    # Since broadcasting the entire array is not necessary, we don't include it
    # in encpedpop.CoordinatorMsg, but only return it as a side output, so that
    # chilldkg.coordinator_step can pick it up. Implementations of pure
    # EncPedPop will need to decide how to transmit enc_secshares[i] to
    # participant i; we leave this unspecified.
    return CoordinatorMsg(simpl_cmsg, pubnonces), dkg_output, eq_input, enc_secshares
