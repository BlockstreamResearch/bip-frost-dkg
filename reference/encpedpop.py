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


class SignerMsg(NamedTuple):
    simpl_smsg: simplpedpop.SignerMsg
    enc_shares: List[Scalar]


class CoordinatorMsg(NamedTuple):
    simpl_cmsg: simplpedpop.CoordinatorMsg
    enc_shares_sum: Scalar


###
### Signer
###


class SignerState(NamedTuple):
    t: int  # TODO This can also be found in simpl_state
    deckey: bytes
    enckeys: List[bytes]
    idx: int
    self_share: Scalar
    simpl_state: simplpedpop.SignerState  # TODO Move up?


def signer_step(
    seed: bytes, t: int, n: int, deckey: bytes, enckeys: List[bytes], idx: int
) -> Tuple[SignerState, SignerMsg]:
    assert t < 2 ** (4 * 8)
    n = len(enckeys)

    # Protect against reuse of seed in case we previously exported shares
    # encrypted under wrong enckeys.
    enc_context = t.to_bytes(4, byteorder="big") + b"".join(enckeys)
    seed_ = tagged_hash_bip_dkg("EncPedPop seed", seed + enc_context)

    simpl_state, simpl_smsg, shares = simplpedpop.signer_step(seed_, t, n, idx)
    assert len(shares) == n
    enc_shares: List[Scalar] = []
    for i in range(n):
        if i == idx:
            # TODO No need to send a constant.
            enc_shares.append(Scalar(0))
        else:
            try:
                enc_shares.append(encrypt(shares[i], deckey, enckeys[i], enc_context))
            except ValueError:  # Invalid enckeys[i]
                raise InvalidContributionError(
                    i, "Participant sent invalid encryption key"
                )
    self_share = shares[idx]
    smsg = SignerMsg(simpl_smsg, enc_shares)
    state = SignerState(t, deckey, enckeys, idx, self_share, simpl_state)
    return state, smsg


def signer_pre_finalize(
    state: SignerState,
    cmsg: CoordinatorMsg,
) -> Tuple[bytes, simplpedpop.DKGOutput]:
    t, deckey, enckeys, idx, self_share, simpl_state = state
    simpl_cmsg, enc_shares_sum = cmsg

    enc_context = t.to_bytes(4, byteorder="big") + b"".join(enckeys)
    shares_sum = decrypt_sum(enc_shares_sum, deckey, enckeys, idx, enc_context)
    shares_sum += self_share
    eta, dkg_output = simplpedpop.signer_pre_finalize(
        simpl_state, simpl_cmsg, shares_sum
    )
    eta += b"".join(enckeys)
    return eta, dkg_output
