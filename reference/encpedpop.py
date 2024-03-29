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


# TODO Define a CoordinatorUnicastMsg to imrpove handling of the enc_shares_sums?


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


def session_seed(seed, enckeys, t):
    enc_context = t.to_bytes(4, byteorder="big") + b"".join(enckeys)
    seed_ = tagged_hash_bip_dkg("EncPedPop seed", seed + enc_context)
    return seed_, enc_context


def signer_step(
    seed: bytes, t: int, n: int, deckey: bytes, enckeys: List[bytes], signer_idx: int
) -> Tuple[SignerState, SignerMsg]:
    assert t < 2 ** (4 * 8)
    n = len(enckeys)

    # Protect against reuse of seed in case we previously exported shares
    # encrypted under wrong enckeys.
    seed_, enc_context = session_seed(seed, enckeys, t)

    simpl_state, simpl_smsg, shares = simplpedpop.signer_step(seed_, t, n, signer_idx)
    assert len(shares) == n
    enc_shares: List[Scalar] = []
    for i in range(n):
        if i == signer_idx:
            # TODO No need to send a constant.
            enc_shares.append(Scalar(0))
        else:
            try:
                enc_shares.append(encrypt(shares[i], deckey, enckeys[i], enc_context))
            except ValueError:  # Invalid enckeys[i]
                raise InvalidContributionError(
                    i, "Participant sent invalid encryption key"
                )
    self_share = shares[signer_idx]
    smsg = SignerMsg(simpl_smsg, enc_shares)
    state = SignerState(t, deckey, enckeys, signer_idx, self_share, simpl_state)
    return state, smsg


def signer_pre_finalize(
    state: SignerState,
    cmsg: CoordinatorMsg,
    enc_shares_sum: Scalar,
) -> Tuple[bytes, simplpedpop.DKGOutput]:
    t, deckey, enckeys, idx, self_share, simpl_state = state
    simpl_cmsg, = cmsg  # Unpack unary tuple  # fmt: skip

    enc_context = t.to_bytes(4, byteorder="big") + b"".join(enckeys)
    shares_sum = decrypt_sum(enc_shares_sum, deckey, enckeys, idx, enc_context)
    shares_sum += self_share
    eta, dkg_output = simplpedpop.signer_pre_finalize(
        simpl_state, simpl_cmsg, shares_sum
    )
    eta += b"".join(enckeys)
    return eta, dkg_output


###
### Coordinator
###


def coordinator_step(
    smsgs: List[SignerMsg], t: int
) -> Tuple[CoordinatorMsg, List[Scalar]]:
    n = len(smsgs)
    simpl_cmsg = simplpedpop.coordinator_step([smsg.simpl_smsg for smsg in smsgs], t)
    enc_shares_sums = [
        Scalar.sum(*([smsg.enc_shares[i] for smsg in smsgs])) for i in range(n)
    ]
    return CoordinatorMsg(simpl_cmsg), enc_shares_sums
