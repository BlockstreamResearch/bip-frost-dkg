from __future__ import annotations

from typing import Tuple, List, NamedTuple, NoReturn

from secp256k1lab.secp256k1 import Scalar, GE
from secp256k1lab.ecdh import ecdh_libsecp256k1
from secp256k1lab.keys import pubkey_gen_plain
from secp256k1lab.util import int_from_bytes

from . import simplpedpop
from .util import (
    UnknownFaultyParticipantOrCoordinatorError,
    tagged_hash_bip_dkg,
    FaultyParticipantOrCoordinatorError,
    FaultyCoordinatorError,
)


###
### Encryption
###


def ecdh(
    seckey: bytes, my_pubkey: bytes, their_pubkey: bytes, context: bytes, sending: bool
) -> Scalar:
    data = ecdh_libsecp256k1(seckey, their_pubkey)
    if sending:
        data += my_pubkey + their_pubkey
    else:
        data += their_pubkey + my_pubkey
    assert len(data) == 32 + 2 * 33
    data += context
    return Scalar(int_from_bytes(tagged_hash_bip_dkg("encpedpop ecdh", data)))


def self_pad(symkey: bytes, nonce: bytes, context: bytes) -> Scalar:
    # Pad for symmetric encryption to ourselves
    return Scalar(
        int_from_bytes(
            tagged_hash_bip_dkg("encaps_multi self_pad", symkey + nonce + context)
        )
    )


def encaps_multi(
    secnonce: bytes,
    pubnonce: bytes,
    deckey: bytes,
    enckeys: List[bytes],
    context: bytes,
    idx: int,
) -> List[Scalar]:
    # This is effectively the "Hashed ElGamal" multi-recipient KEM described in
    # Section 5 of "Multi-recipient encryption, revisited" by Alexandre Pinto,
    # Bertram Poettering, Jacob C. N. Schuldt (AsiaCCS 2014). Its crucial
    # feature is to feed the index of the enckey to the hash function. The only
    # difference is that we feed also the pubnonce and context data into the
    # hash function.
    pads = []
    for i, enckey in enumerate(enckeys):
        context_ = i.to_bytes(4, byteorder="big") + context
        if i == idx:
            # We're encrypting to ourselves, so we use a symmetrically derived
            # pad to save the ECDH computation.
            pad = self_pad(symkey=deckey, nonce=pubnonce, context=context_)
        else:
            pad = ecdh(
                seckey=secnonce,
                my_pubkey=pubnonce,
                their_pubkey=enckey,
                context=context_,
                sending=True,
            )
        pads.append(pad)
    return pads


def encrypt_multi(
    secnonce: bytes,
    pubnonce: bytes,
    deckey: bytes,
    enckeys: List[bytes],
    context: bytes,
    idx: int,
    plaintexts: List[Scalar],
) -> List[Scalar]:
    pads = encaps_multi(secnonce, pubnonce, deckey, enckeys, context, idx)
    assert len(plaintexts) == len(pads)
    ciphertexts = [plaintext + pad for plaintext, pad in zip(plaintexts, pads)]
    return ciphertexts


def decaps_multi(
    deckey: bytes,
    enckey: bytes,
    pubnonces: List[bytes],
    context: bytes,
    idx: int,
) -> List[Scalar]:
    context_ = idx.to_bytes(4, byteorder="big") + context
    pads = []
    for sender_idx, pubnonce in enumerate(pubnonces):
        if sender_idx == idx:
            pad = self_pad(symkey=deckey, nonce=pubnonce, context=context_)
        else:
            pad = ecdh(
                seckey=deckey,
                my_pubkey=enckey,
                their_pubkey=pubnonce,
                context=context_,
                sending=False,
            )
        pads.append(pad)
    return pads


def decrypt_sum(
    deckey: bytes,
    enckey: bytes,
    pubnonces: List[bytes],
    context: bytes,
    idx: int,
    sum_ciphertexts: Scalar,
) -> Scalar:
    if idx >= len(pubnonces):
        raise IndexError
    pads = decaps_multi(deckey, enckey, pubnonces, context, idx)
    sum_plaintexts: Scalar = sum_ciphertexts - Scalar.sum(*pads)
    return sum_plaintexts


###
### Messages
###


class ParticipantMsg(NamedTuple):
    simpl_pmsg: simplpedpop.ParticipantMsg
    pubnonce: bytes
    enc_shares: List[Scalar]

    def to_bytes(self) -> bytes:
        return (
            self.simpl_pmsg.to_bytes()
            + self.pubnonce
            + b"".join(share.to_bytes() for share in self.enc_shares)
        )

    @staticmethod
    def from_bytes_and_n(b: bytes, n: int) -> ParticipantMsg:
        rest = b

        # Read enc_shares (32*n bytes)
        if len(rest) < 32 * n:
            raise ValueError
        enc_secshares, rest = (
            [
                Scalar.from_bytes(rest[i : i + 32])
                for i in range(len(rest) - 32 * n, len(rest), 32)
            ],
            rest[: len(rest) - 32 * n],
        )

        # Read pubnonce (33 bytes)
        if len(rest) < 33:
            raise ValueError
        pubnonce, rest = rest[-33:], rest[:-33]

        # Read simpl_pmsg
        simpl_pmsg = simplpedpop.ParticipantMsg.from_bytes(rest)

        # len(rest) check is unnecessary. simpl_pmg raises ValueError
        # if `rest` isn't fully consumed
        return ParticipantMsg(simpl_pmsg, pubnonce, enc_secshares)


class CoordinatorMsg(NamedTuple):
    simpl_cmsg: simplpedpop.CoordinatorMsg
    pubnonces: List[bytes]

    def to_bytes(self) -> bytes:
        return self.simpl_cmsg.to_bytes() + b"".join(self.pubnonces)

    @staticmethod
    def from_bytes_and_n(b: bytes, n: int) -> CoordinatorMsg:
        rest = b

        # Read pubnonces (33*n bytes)
        if len(rest) < 33 * n:
            raise ValueError
        pubnonces, rest = (
            [rest[i : i + 33] for i in range(len(rest) - 33 * n, len(rest), 33)],
            rest[: len(rest) - 33 * n],
        )

        # Read simpl_cmsg
        simpl_cmsg = simplpedpop.CoordinatorMsg.from_bytes_and_n(rest, n)

        # len(rest) check is unnecessary. simpl_cmg raises ValueError
        # if `rest`` isn't fully consumed
        return CoordinatorMsg(simpl_cmsg, pubnonces)


class CoordinatorInvestigationMsg(NamedTuple):
    enc_partial_secshares: List[Scalar]
    partial_pubshares: List[GE]

    def to_bytes(self) -> bytes:
        secshares_bytes = b"".join(
            share.to_bytes() for share in self.enc_partial_secshares
        )
        pubshares_bytes = b"".join(
            P.to_bytes_compressed_with_infinity() for P in self.partial_pubshares
        )
        return secshares_bytes + pubshares_bytes

    @staticmethod
    def from_bytes(b: bytes) -> CoordinatorInvestigationMsg:
        rest = b

        # Compute n
        n, remainder = divmod(len(rest), (32 + 33))
        if remainder != 0:
            raise ValueError

        # Read enc_partial_secshares (32*n bytes)
        if len(rest) < 32 * n:
            raise ValueError
        enc_partial_secshares, rest = (
            [Scalar.from_bytes(rest[i : i + 32]) for i in range(0, 32 * n, 32)],
            rest[32 * n :],
        )

        # Read partial_pubshares (33*n bytes)
        if len(rest) < 33 * n:
            raise ValueError
        partial_pubshares, rest = (
            [
                GE.from_bytes_with_infinity(rest[i : i + 33])
                for i in range(0, 33 * n, 33)
            ],
            rest[33 * n :],
        )

        if len(rest) != 0:
            raise ValueError
        return CoordinatorInvestigationMsg(enc_partial_secshares, partial_pubshares)


###
### Participant
###


class ParticipantState(NamedTuple):
    simpl_state: simplpedpop.ParticipantState
    pubnonce: bytes
    enckeys: List[bytes]
    idx: int


class ParticipantInvestigationData(NamedTuple):
    simpl_bstate: simplpedpop.ParticipantInvestigationData
    enc_secshare: Scalar
    pads: List[Scalar]


def serialize_enc_context(t: int, enckeys: List[bytes]) -> bytes:
    return t.to_bytes(4, byteorder="big") + b"".join(enckeys)


def participant_step1(
    seed: bytes,
    deckey: bytes,
    enckeys: List[bytes],
    t: int,
    idx: int,
    random: bytes,
) -> Tuple[ParticipantState, bytes]:
    assert t < 2 ** (4 * 8)
    assert len(random) == 32
    n = len(enckeys)

    # Derive an encryption nonce and a seed for SimplPedPop.
    #
    # SimplPedPop will use its seed to derive the secret shares, which we will
    # encrypt using the encryption nonce. That means that all entropy used in
    # the derivation of simpl_seed should also be in the derivation of the
    # pubnonce, to ensure that we never encrypt different secret shares with the
    # same encryption pads. The foolproof way to achieve this is to simply
    # derive the nonce from simpl_seed.
    enc_context = serialize_enc_context(t, enckeys)
    simpl_seed = tagged_hash_bip_dkg("encpedpop seed", seed + random + enc_context)
    secnonce = tagged_hash_bip_dkg("encpedpop secnonce", simpl_seed)
    pubnonce = pubkey_gen_plain(secnonce)

    simpl_state, simpl_pmsg, shares = simplpedpop.participant_step1(
        simpl_seed, t, n, idx
    )
    assert len(shares) == n

    enc_shares = encrypt_multi(
        secnonce, pubnonce, deckey, enckeys, enc_context, idx, shares
    )
    simpl_pmsg_parsed = simplpedpop.ParticipantMsg.from_bytes(simpl_pmsg)

    pmsg = ParticipantMsg(simpl_pmsg_parsed, pubnonce, enc_shares).to_bytes()
    state = ParticipantState(simpl_state, pubnonce, enckeys, idx)
    return state, pmsg


def participant_step2(
    state: ParticipantState,
    deckey: bytes,
    cmsg: bytes,
    enc_secshare: Scalar,
) -> Tuple[simplpedpop.DKGOutput, bytes]:
    simpl_state, pubnonce, enckeys, idx = state
    cmsg_parsed = CoordinatorMsg.from_bytes_and_n(cmsg, len(enckeys))
    simpl_cmsg, pubnonces = cmsg_parsed

    reported_pubnonce = pubnonces[idx]
    if reported_pubnonce != pubnonce:
        raise FaultyCoordinatorError("Coordinator replied with wrong pubnonce")

    enc_context = serialize_enc_context(simpl_state.t, enckeys)
    pads = decaps_multi(deckey, enckeys[idx], pubnonces, enc_context, idx)
    secshare = enc_secshare - Scalar.sum(*pads)

    try:
        dkg_output, eq_input = simplpedpop.participant_step2(
            simpl_state, simpl_cmsg.to_bytes(), secshare
        )
    except UnknownFaultyParticipantOrCoordinatorError as e:
        assert isinstance(e.inv_data, simplpedpop.ParticipantInvestigationData)
        # Translate simplpedpop.ParticipantInvestigationData into our own
        # encpedpop.ParticipantInvestigationData.
        inv_data = ParticipantInvestigationData(e.inv_data, enc_secshare, pads)
        raise UnknownFaultyParticipantOrCoordinatorError(inv_data, e.args) from e

    eq_input += b"".join(enckeys) + b"".join(pubnonces)
    return dkg_output, eq_input


def participant_investigate(
    error: UnknownFaultyParticipantOrCoordinatorError,
    cinv: bytes,
) -> NoReturn:
    simpl_inv_data, enc_secshare, pads = error.inv_data
    cinv_parsed = CoordinatorInvestigationMsg.from_bytes(cinv)
    enc_partial_secshares, partial_pubshares = cinv_parsed
    assert len(enc_partial_secshares) == len(pads)
    partial_secshares = [
        enc_partial_secshare - pad
        for enc_partial_secshare, pad in zip(enc_partial_secshares, pads)
    ]

    simpl_cinv = simplpedpop.CoordinatorInvestigationMsg(partial_pubshares)
    try:
        simplpedpop.participant_investigate(
            UnknownFaultyParticipantOrCoordinatorError(simpl_inv_data),
            simpl_cinv.to_bytes(),
            partial_secshares,
        )
    except simplpedpop.SecshareSumError as e:
        # The secshare is not equal to the sum of the partial secshares in the
        # investigation message. Since the encryption is additively homomorphic,
        # this can only happen if the sum of the *encrypted* secshare is not
        # equal to the sum of the encrypted partial sechares, which is the
        # coordinator's fault.
        assert Scalar.sum(*enc_partial_secshares) != enc_secshare
        raise FaultyCoordinatorError(
            "Sum of encrypted partial secshares not equal to encrypted secshare"
        ) from e


###
### Coordinator
###


def coordinator_step(
    pmsgs: List[bytes],
    t: int,
    enckeys: List[bytes],
) -> Tuple[bytes, simplpedpop.DKGOutput, bytes, List[Scalar]]:
    n = len(enckeys)
    if n != len(pmsgs):
        raise ValueError

    pmsgs_parsed = [ParticipantMsg.from_bytes_and_n(pmsg, n) for pmsg in pmsgs]
    simpl_cmsg, dkg_output, eq_input = simplpedpop.coordinator_step(
        pmsgs=[pmsg.simpl_pmsg.to_bytes() for pmsg in pmsgs_parsed], t=t, n=n
    )
    simpl_cmsg_parsed = simplpedpop.CoordinatorMsg.from_bytes_and_n(simpl_cmsg, n)
    pubnonces = [pmsg.pubnonce for pmsg in pmsgs_parsed]
    for i in range(n):
        if len(pmsgs_parsed[i].enc_shares) != n:
            raise FaultyParticipantOrCoordinatorError(
                i, "Participant sent enc_shares with invalid length"
            )
    enc_secshares = [
        Scalar.sum(*([pmsg.enc_shares[i] for pmsg in pmsgs_parsed])) for i in range(n)
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
    # participant i for participant_step2(); we leave this unspecified.
    return (
        CoordinatorMsg(simpl_cmsg_parsed, pubnonces).to_bytes(),
        dkg_output,
        eq_input,
        enc_secshares,
    )


def coordinator_investigate(
    pmsgs: List[bytes],
) -> List[bytes]:
    n = len(pmsgs)
    pmsgs_parsed = [ParticipantMsg.from_bytes_and_n(pmsg, n) for pmsg in pmsgs]
    simpl_pmsgs = [pmsg.simpl_pmsg.to_bytes() for pmsg in pmsgs_parsed]

    all_enc_partial_secshares = [
        [pmsg.enc_shares[i] for pmsg in pmsgs_parsed] for i in range(n)
    ]
    simpl_cinvs = simplpedpop.coordinator_investigate(simpl_pmsgs)
    simpl_cinvs_parsed = [
        simplpedpop.CoordinatorInvestigationMsg.from_bytes(simpl_cinv)
        for simpl_cinv in simpl_cinvs
    ]
    cinvs = [
        CoordinatorInvestigationMsg(
            all_enc_partial_secshares[i], simpl_cinvs_parsed[i].partial_pubshares
        ).to_bytes()
        for i in range(n)
    ]
    return cinvs
