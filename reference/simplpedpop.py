from secrets import token_bytes as random_bytes
from typing import List, NamedTuple, NewType, Tuple, Optional

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
    sig = schnorr_sign(pop_msg(idx), seckey, aux_rand=random_bytes(32))
    return Pop(sig)


def pop_verify(pop: Pop, pubkey: bytes, idx: int):
    return schnorr_verify(pop_msg(idx), pubkey, pop)


###
### Messages
###


class ParticipantMsg(NamedTuple):
    """Round 1 message from participant to coordinator"""

    com: VSSCommitment
    pop: Pop


class CoordinatorMsg(NamedTuple):
    """Round 1 message from coordinator to all participants"""

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


###
### Other common definitions
###


# TODO This should probably moved somewhere else as its common to all DKGs.
# Hm, moving it to reference.py is difficult due to cylic module dependencies.
class DKGOutput(NamedTuple):
    secshare: Optional[Scalar]  # None for coordinator
    threshold_pubkey: GE
    pubshares: List[GE]


def assemble_sum_vss_commitment(
    coms_to_secrets: List[GE], sum_coms_to_nonconst_terms: List[GE], n: int
) -> VSSCommitment:
    # Sum the commitments to the secrets
    return VSSCommitment(
        [GE.sum(*(coms_to_secrets[i] for i in range(n)))] + sum_coms_to_nonconst_terms
    )


def common_dkg_output(vss_commit, n: int) -> Tuple[GE, List[GE]]:
    """Derive the common parts of the DKG output from the sum of all VSS commitments

    The common parts are the threshold public key and the individual public shares of
    all participants."""
    threshold_pubkey = vss_commit.ges[0]
    pubshares = []
    for i in range(0, n):
        # TODO The following computation is the major part of vss_commit.verify(i, ...),
        # which we have already computed for i. We should 1) extract the major part of
        # VSSCommitment.verify into a separate method, and 2) avoid that we're computing
        # it twice here.
        pk_i = GE.batch_mul(
            *(((i + 1) ** j, vss_commit.ges[j]) for j in range(0, vss_commit.t()))
        )
        pubshares += [pk_i]
    return threshold_pubkey, pubshares


###
### Participant
###


class ParticipantState(NamedTuple):
    t: int
    n: int
    idx: int
    com_to_secret: GE


# To keep the algorithms of SimplPedPop and EncPedPop purely non-interactive computations,
# we omit explicit invocations of an interactive equality check protocol.
# ChillDKG will take care of invoking the equality check protocol.


def participant_step1(
    seed: bytes, t: int, n: int, participant_idx: int
) -> Tuple[ParticipantState, ParticipantMsg, List[Scalar]]:
    """
    Generate SimplPedPop messages to be sent to the coordinator.

    :param bytes seed: FRESH, UNIFORMLY RANDOM 32-byte string
    :param int t: threshold
    :param int n: number of participants
    :param int participant_idx: index of this participant in the participant list
    :return: the participant's state, the VSS commitment and the generated shares
    """
    assert t < 2 ** (4 * 8)
    assert participant_idx < 2 ** (4 * 8)

    vss = VSS.generate(seed, t)
    shares = vss.shares(n)
    pop = pop_prove(vss.secret().to_bytes(), participant_idx)

    vss_commit = vss.commit()
    com_to_secret = vss_commit.commitment_to_secret()
    msg = ParticipantMsg(vss_commit, pop)
    state = ParticipantState(t, n, participant_idx, com_to_secret)
    return state, msg, shares


def participant_step2(
    state: ParticipantState,
    cmsg: CoordinatorMsg,
    shares_sum: Scalar,
) -> Tuple[DKGOutput, bytes]:
    """
    Take the messages received from the coordinator and return eq_input to be compared and DKG output

    :param ParticipantState state: the participant's state after round 1 (output by participant_round1)
    :param CoordinatorMsg cmsg: round 1 broadcast message received from the coordinator
    :param Scalar shares_sum: sum of shares for this participant received from all participants (including this participant)
    :return: the data `eq_input` that must be input to an equality check protocol, the final share, the threshold pubkey, the individual participants' pubshares
    """
    t, n, idx, com_to_secret = state
    coms_to_secrets, sum_coms_to_nonconst_terms, pops = cmsg
    assert len(coms_to_secrets) == n
    assert len(sum_coms_to_nonconst_terms) == t - 1
    assert len(pops) == n

    if coms_to_secrets[idx] != com_to_secret:
        raise InvalidContributionError(
            None, "Coordinator sent unexpected first group element for local index"
        )

    for i in range(n):
        if i == idx:
            # No need to check our own pop.
            continue
        if coms_to_secrets[i].infinity:
            raise InvalidContributionError(i, "Participant sent invalid commitment")
        # This can be optimized: We serialize the coms_to_secrets[i] here, but
        # schnorr_verify (inside pop_verify) will need to deserialize it again, which
        # involves computing a square root to obtain the y coordinate.
        if not pop_verify(pops[i], coms_to_secrets[i].to_bytes_xonly(), i):
            raise InvalidContributionError(
                i, "Participant sent invalid proof-of-knowledge"
            )
    sum_vss_commit = assemble_sum_vss_commitment(
        coms_to_secrets, sum_coms_to_nonconst_terms, n
    )
    if not sum_vss_commit.verify(idx, shares_sum):
        raise VSSVerifyError()
    threshold_pubkey, pubshares = common_dkg_output(sum_vss_commit, n)
    eq_input = t.to_bytes(4, byteorder="big") + sum_vss_commit.to_bytes()
    return DKGOutput(shares_sum, threshold_pubkey, pubshares), eq_input


###
### Coordinator
###


# Sum the commitments to the i-th coefficients from the given vss_commitments
# for i > 0. This procedure is introduced by Pedersen in section 5.1 of
# 'Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing'.
def coordinator_step(
    pmsgs: List[ParticipantMsg], t: int, n: int
) -> Tuple[CoordinatorMsg, DKGOutput, bytes]:
    # We cannot sum the commitments to the secrets because they'll be necessary
    # to check the PoPs.
    coms_to_secrets = [pmsg.com.commitment_to_secret() for pmsg in pmsgs]
    # But we can sum the commitments to the non-constant terms.
    sum_coms_to_nonconst_terms = [
        GE.sum(*(pmsg.com.commitment_to_nonconst_terms()[j] for pmsg in pmsgs))
        for j in range(0, t - 1)
    ]
    pops = [pmsg.pop for pmsg in pmsgs]
    sum_vss_commit = assemble_sum_vss_commitment(
        coms_to_secrets, sum_coms_to_nonconst_terms, n
    )
    threshold_pubkey, pubshares = common_dkg_output(sum_vss_commit, n)
    dkg_output = DKGOutput(None, threshold_pubkey, pubshares)
    eq_input = t.to_bytes(4, byteorder="big") + sum_vss_commit.to_bytes()
    return (
        CoordinatorMsg(coms_to_secrets, sum_coms_to_nonconst_terms, pops),
        dkg_output,
        eq_input,
    )
