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


def pop_prove(seckey, my_idx, aux_rand: bytes = 32 * b"\x00"):
    # TODO: What to do with aux_rand?
    sig = schnorr_sign(pop_msg(my_idx), seckey, aux_rand)
    return Pop(sig)


def pop_verify(pop: Pop, pubkey: bytes, idx: int):
    return schnorr_verify(pop_msg(idx), pubkey, pop)


###
### Messages
###


class Unicast1(NamedTuple):
    """Round 1 message from signer to coordinator"""

    com: VSSCommitment
    pop: Pop


class Broadcast1(NamedTuple):
    """Round 1 message from coordinator to all signers"""

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


def aggregate_vss_commitments(
    first_ges: List[GE], remaining_ges: List[GE], t: int, n: int
) -> VSSCommitment:
    # Sum the commitments to the constant coefficients
    return VSSCommitment([GE.sum(*(first_ges[i] for i in range(n)))] + remaining_ges)


###
### Signer
###


class SignerState1(NamedTuple):
    t: int
    n: int
    my_idx: int
    my_first_ge: GE


# TODO This should probably moved somewhere else as its common to all DKGs
class DKGOutput(NamedTuple):
    share: Scalar
    shared_pubkey: GE
    pubkeys: List[GE]


# To keep the algorithms of SimplPedPop and EncPedPop purely non-interactive computations,
# we omit explicit invocations of an interactive equality check protocol.
# ChillDKG will take care of invoking the equality check protocol.


def signer_round1(
    seed: bytes, t: int, n: int, my_idx: int
) -> Tuple[SignerState1, Unicast1, List[Scalar]]:
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
    pop = pop_prove(vss.secret().to_bytes(), my_idx)

    vss_commitment = vss.commit()
    my_first_ge = vss_commitment.ges[0]
    msg = Unicast1(vss_commitment, pop)
    state = SignerState1(t, n, my_idx, my_first_ge)
    return state, msg, shares


def signer_pre_finalize(
    state: SignerState1,
    msg: Broadcast1,
    shares_sum: Scalar,
) -> Tuple[bytes, DKGOutput]:
    """
    Take the messages received from the coordinator and return eta to be compared and DKG output

    :param SignerState state: the signer's state after round 1 (output by signer_round1)
    :param Broadcast1 msgs: round 1 broadcast message received from the coordinator
    :param Scalar shares_sum: sum of shares for this participant received from all participants (including this participant)
    :return: the data `eta` that must be input to an equality check protocol, the final share, the shared pubkey, the individual participants' pubkeys
    """
    t, n, my_idx, my_first_ge = state
    first_ges, remaining_ges, pops = msg
    assert len(first_ges) == n
    assert len(remaining_ges) == t - 1
    assert len(pops) == n

    if first_ges[my_idx] != my_first_ge:
        raise InvalidContributionError(
            None, "Coordinator sent unexpected first group element for local index"
        )

    for i in range(n):
        if i == my_idx:
            # No need to check our own pop.
            # TODO Should we include a simple bytes comparison as defense-in-depth?
            continue
        if first_ges[i].infinity:
            # TODO This branch can go away once we add real serializations.
            # If the serialized pubkey is infinity, pop_verify will simply fail.
            raise InvalidContributionError(i, "Participant sent invalid commitment")
        else:
            if not pop_verify(pops[i], first_ges[i].to_bytes_xonly(), i):
                raise InvalidContributionError(
                    i, "Participant sent invalid proof-of-knowledge"
                )
    vss_commitment = aggregate_vss_commitments(first_ges, remaining_ges, t, n)
    if not vss_commitment.verify(my_idx, shares_sum):
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
def coordinator_round1(coms: List[Unicast1], t: int) -> Broadcast1:
    first_ges = [com[0].ges[0] for com in coms]
    remaining_ges_sum = [GE.sum(*(com[0].ges[j] for com in coms)) for j in range(1, t)]
    pops = [com[1] for com in coms]
    return Broadcast1(first_ges, remaining_ges_sum, pops)
