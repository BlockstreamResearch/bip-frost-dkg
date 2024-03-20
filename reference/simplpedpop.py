from typing import List, NamedTuple, NewType, Tuple

from secp256k1ref.bip340 import schnorr_sign, schnorr_verify
from secp256k1ref.secp256k1 import GE, Scalar
from util import BIP_TAG, InvalidContributionError
from vss import VSS, VSSCommitment, VSSVerifyError


###
### Proofs of possession (Pops)
###


Pop = NewType("Pop", bytes)

POP_MSG_TAG = (BIP_TAG + "pop message").encode()


def pop_msg(idx: int):
    return POP_MSG_TAG + idx.to_bytes(4, byteorder="big")


def pop_prove(seckey, idx, aux_rand: bytes = 32 * b"\x00"):
    # TODO: What to do with aux_rand?
    sig = schnorr_sign(pop_msg(idx), seckey, aux_rand)
    return Pop(sig)


def pop_verify(pop: Pop, pubkey: bytes, idx: int):
    return schnorr_verify(pop_msg(idx), pubkey, pop)


###
### Messages
###


class SignerMsg(NamedTuple):
    """Round 1 message from signer to coordinator"""

    com: VSSCommitment
    pop: Pop


class CoordinatorMsg(NamedTuple):
    """Round 1 message from coordinator to all signers"""

    coms_to_secrets: List[GE]
    sum_coms_to_nonconst_terms: List[GE]
    pops: List[Pop]

    def to_bytes(self) -> bytes:
        return b"".join(
            [
                P.to_bytes_compressed_with_infinity()
                for P in self.coms_to_secrets + self.sum_coms_to_nonconst_terms
            ]
        ) + b"".join(self.pops)


def assemble_sum_vss_commitment(
    coms_to_secrets: List[GE], sum_coms_to_nonconst_terms: List[GE], t: int, n: int
) -> VSSCommitment:
    # Sum the commitments to the secrets
    return VSSCommitment(
        [GE.sum(*(coms_to_secrets[i] for i in range(n)))] + sum_coms_to_nonconst_terms
    )


###
### Signer
###


class SignerState(NamedTuple):
    t: int
    n: int
    idx: int
    com_to_secret: GE


# TODO This should probably moved somewhere else as its common to all DKGs
class DKGOutput(NamedTuple):
    share: Scalar
    shared_pubkey: GE
    pubkeys: List[GE]


# To keep the algorithms of SimplPedPop and EncPedPop purely non-interactive computations,
# we omit explicit invocations of an interactive equality check protocol.
# ChillDKG will take care of invoking the equality check protocol.


def signer_step(
    seed: bytes, t: int, n: int, idx: int
) -> Tuple[SignerState, SignerMsg, List[Scalar]]:
    """
    Generate SimplPedPop messages to be sent to the coordinator.

    :param bytes seed: FRESH, UNIFORMLY RANDOM 32-byte string
    :param int t: threshold
    :param int n: number of participants
    :param int idx: index of this signer in the participant list
    :return: the signer's state, the VSS commitment and the generated shares
    """
    assert t < 2 ** (4 * 8)
    assert idx < 2 ** (4 * 8)

    vss = VSS.generate(seed, t)
    shares = vss.shares(n)
    pop = pop_prove(vss.secret().to_bytes(), idx)

    vss_commitment = vss.commit()
    com_to_secret = vss_commitment.commitment_to_secret()
    msg = SignerMsg(vss_commitment, pop)
    state = SignerState(t, n, idx, com_to_secret)
    return state, msg, shares


def signer_pre_finalize(
    state: SignerState,
    cmsg: CoordinatorMsg,
    shares_sum: Scalar,
) -> Tuple[bytes, DKGOutput]:
    """
    Take the messages received from the coordinator and return eta to be compared and DKG output

    :param SignerState state: the signer's state after round 1 (output by signer_round1)
    :param CoordinatorMsg cmsg: round 1 broadcast message received from the coordinator
    :param Scalar shares_sum: sum of shares for this participant received from all participants (including this participant)
    :return: the data `eta` that must be input to an equality check protocol, the final share, the shared pubkey, the individual participants' pubkeys
    """
    t, n, idx, com_to_secret = state
    coms_to_secrets, coms_to_nonconst_terms, pops = cmsg
    assert len(coms_to_secrets) == n
    assert len(coms_to_nonconst_terms) == t - 1
    assert len(pops) == n

    if coms_to_secrets[idx] != com_to_secret:
        raise InvalidContributionError(
            None, "Coordinator sent unexpected first group element for local index"
        )

    for i in range(n):
        if i == idx:
            # No need to check our own pop.
            # TODO Should we include a simple bytes comparison as defense-in-depth?
            continue
        if coms_to_secrets[i].infinity:
            # TODO This branch can go away once we add real serializations.
            # If the serialized pubkey is infinity, pop_verify will simply fail.
            raise InvalidContributionError(i, "Participant sent invalid commitment")
        else:
            if not pop_verify(pops[i], coms_to_secrets[i].to_bytes_xonly(), i):
                raise InvalidContributionError(
                    i, "Participant sent invalid proof-of-knowledge"
                )
    vss_commitment = assemble_sum_vss_commitment(
        coms_to_secrets, coms_to_nonconst_terms, t, n
    )
    if not vss_commitment.verify(idx, shares_sum):
        raise VSSVerifyError()
    eta = t.to_bytes(4, byteorder="big") + vss_commitment.to_bytes()
    shared_pubkey, signer_pubkeys = vss_commitment.group_info(n)
    return eta, DKGOutput(shares_sum, shared_pubkey, signer_pubkeys)


###
### Coordinator
###


# Sum the commitments to the i-th coefficients from the given vss_commitments
# for i > 0. This procedure is introduced by Pedersen in section 5.1 of
# 'Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing'.
def coordinator_step(smsgs: List[SignerMsg], t: int) -> CoordinatorMsg:
    coms_to_secrets = [smsg.com.commitment_to_secret() for smsg in smsgs]
    sum_coms_to_nonconst_terms = [
        GE.sum(*(smsg.com.commitment_to_nonconst_terms()[j] for smsg in smsgs))
        for j in range(0, t - 1)
    ]
    pops = [smsg.pop for smsg in smsgs]
    return CoordinatorMsg(coms_to_secrets, sum_coms_to_nonconst_terms, pops)
