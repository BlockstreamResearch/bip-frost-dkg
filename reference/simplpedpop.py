from typing import Tuple, List, NamedTuple

from secp256k1ref.secp256k1 import GE, Scalar
from secp256k1ref.bip340 import schnorr_sign, schnorr_verify


from vss import VSS, VSSCommitment
from util import (
    kdf,
    BIP_TAG,
    InvalidContributionError,
    VSSVerifyError,
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
