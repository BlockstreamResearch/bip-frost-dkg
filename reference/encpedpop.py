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


###
### Messages
###


class Unicast1(NamedTuple):
    simpl_state: simplpedpop.Unicast1
    enc_shares: List[Scalar]


class Broadcast1(NamedTuple):
    simpl_broad1: simplpedpop.Broadcast1
    enc_shares_sum: Scalar


###
### Signer
###


class SignerState1(NamedTuple):
    t: int  # TODO This can also be found in simpl_state
    deckey: bytes
    enckeys: List[bytes]
    my_idx: int
    self_share: Scalar
    simpl_state: simplpedpop.SignerState1  # TODO Move up?


def signer_round1(
    seed: bytes, t: int, n: int, my_deckey: bytes, enckeys: List[bytes], my_idx: int
) -> Tuple[SignerState1, Unicast1]:
    assert t < 2 ** (4 * 8)
    n = len(enckeys)

    # Protect against reuse of seed in case we previously exported shares
    # encrypted under wrong enckeys.
    enc_context = t.to_bytes(4, byteorder="big") + b"".join(enckeys)
    seed_ = tagged_hash_bip_dkg("EncPedPop seed", seed + enc_context)

    simpl_state, simpl_uni1, shares = simplpedpop.signer_round1(seed_, t, n, my_idx)
    assert len(shares) == n
    enc_shares: List[Scalar] = []
    for i in range(n):
        if i == my_idx:
            # TODO No need to send a constant.
            enc_shares.append(Scalar(0))
        else:
            try:
                enc_shares.append(
                    encrypt(shares[i], my_deckey, enckeys[i], enc_context)
                )
            except ValueError:  # Invalid enckeys[i]
                raise InvalidContributionError(
                    i, "Participant sent invalid encryption key"
                )
    self_share = shares[my_idx]
    uni1 = Unicast1(simpl_uni1, enc_shares)
    state1 = SignerState1(t, my_deckey, enckeys, my_idx, self_share, simpl_state)
    return state1, uni1


def signer_pre_finalize(
    state1: SignerState1,
    broad1: Broadcast1,
) -> Tuple[bytes, simplpedpop.DKGOutput]:
    t, my_deckey, enckeys, my_idx, self_share, simpl_state = state1
    simpl_broad1, enc_shares_sum = broad1

    enc_context = t.to_bytes(4, byteorder="big") + b"".join(enckeys)
    shares_sum = decrypt_sum(enc_shares_sum, my_deckey, enckeys, my_idx, enc_context)
    shares_sum += self_share
    eta, dkg_output = simplpedpop.signer_pre_finalize(
        simpl_state, simpl_broad1, shares_sum
    )
    eta += b"".join(enckeys)
    return eta, dkg_output
