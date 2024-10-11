from secrets import token_bytes as random_bytes
from typing import List, NamedTuple, NewType, Tuple, Optional

from secp256k1proto.bip340 import schnorr_sign, schnorr_verify
from secp256k1proto.secp256k1 import GE, Scalar
from .util import BIP_TAG, SecretKeyError, InvalidContributionError, ThresholdError
from .vss import VSS, VSSCommitment


###
### Proofs of possession (pops)
###


Pop = NewType("Pop", bytes)

POP_MSG_TAG = BIP_TAG + "pop message"


def pop_msg(idx: int) -> bytes:
    return idx.to_bytes(4, byteorder="big")


def pop_prove(seckey: bytes, idx: int, aux_rand: bytes = 32 * b"\x00") -> Pop:
    sig = schnorr_sign(
        pop_msg(idx), seckey, aux_rand=random_bytes(32), challenge_tag=POP_MSG_TAG
    )
    return Pop(sig)


def pop_verify(pop: Pop, pubkey: bytes, idx: int) -> bool:
    return schnorr_verify(pop_msg(idx), pubkey, pop, challenge_tag=POP_MSG_TAG)


###
### Messages
###


class ParticipantMsg(NamedTuple):
    com: VSSCommitment
    pop: Pop


class CoordinatorMsg(NamedTuple):
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


class DKGOutput(NamedTuple):
    secshare: Optional[bytes]  # None for coordinator
    threshold_pubkey: bytes
    pubshares: List[bytes]


def assemble_sum_coms(
    coms_to_secrets: List[GE], sum_coms_to_nonconst_terms: List[GE], n: int
) -> VSSCommitment:
    # Sum the commitments to the secrets
    return VSSCommitment(
        [GE.sum(*(coms_to_secrets[i] for i in range(n)))] + sum_coms_to_nonconst_terms
    )


###
### Participant
###


class ParticipantState(NamedTuple):
    t: int
    n: int
    idx: int
    com_to_secret: GE


# To keep the algorithms of SimplPedPop and EncPedPop purely non-interactive
# computations, we omit explicit invocations of an interactive equality check
# protocol. ChillDKG will take care of invoking the equality check protocol.


def participant_step1(
    seed: bytes, t: int, n: int, idx: int
) -> Tuple[ParticipantState, ParticipantMsg, List[Scalar]]:
    if t > n:
        raise ThresholdError
    if idx >= n:
        raise IndexError
    if len(seed) != 32:
        raise SecretKeyError

    vss = VSS.generate(seed, t)  # OverflowError if t >= 2**32
    shares = vss.secshares(n)
    pop = pop_prove(vss.secret().to_bytes(), idx)

    com = vss.commit()
    com_to_secret = com.commitment_to_secret()
    msg = ParticipantMsg(com, pop)
    state = ParticipantState(t, n, idx, com_to_secret)
    return state, msg, shares


def participant_step2(
    state: ParticipantState,
    cmsg: CoordinatorMsg,
    secshare: Scalar,
) -> Tuple[DKGOutput, bytes]:
    t, n, idx, com_to_secret = state
    coms_to_secrets, sum_coms_to_nonconst_terms, pops = cmsg

    # TODO Raise InvalidContributionError when deserizaltion yields wrong lengths
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
    sum_coms = assemble_sum_coms(coms_to_secrets, sum_coms_to_nonconst_terms, n)
    threshold_pubkey = sum_coms.commitment_to_secret()
    pubshares = [sum_coms.pubshare(i) for i in range(n)]
    if not VSSCommitment.verify_secshare(secshare, pubshares[idx]):
        # TODO What to raise here? We don't know who was wrong.
        raise InvalidContributionError(None, "Received invalid secshare.")

    dkg_output = DKGOutput(
        secshare.to_bytes(),
        threshold_pubkey.to_bytes_compressed(),
        [pubshare.to_bytes_compressed() for pubshare in pubshares],
    )
    eq_input = t.to_bytes(4, byteorder="big") + sum_coms.to_bytes()
    return dkg_output, eq_input


###
### Coordinator
###


def coordinator_step(
    pmsgs: List[ParticipantMsg], t: int, n: int
) -> Tuple[CoordinatorMsg, DKGOutput, bytes]:
    # Sum the commitments to the i-th coefficients for i > 0
    #
    # This procedure corresponds to the one described by Pedersen in Section 5.1
    # of "Non-Interactive and Information-Theoretic Secure Verifiable Secret
    # Sharing". However, we don't sum the commitments to the secrets (i == 0)
    # because they'll be necessary to check the pops.
    coms_to_secrets = [pmsg.com.commitment_to_secret() for pmsg in pmsgs]
    # But we can sum the commitments to the non-constant terms.
    sum_coms_to_nonconst_terms = [
        GE.sum(*(pmsg.com.commitment_to_nonconst_terms()[j] for pmsg in pmsgs))
        for j in range(t - 1)
    ]
    pops = [pmsg.pop for pmsg in pmsgs]
    cmsg = CoordinatorMsg(coms_to_secrets, sum_coms_to_nonconst_terms, pops)

    sum_coms = assemble_sum_coms(coms_to_secrets, sum_coms_to_nonconst_terms, n)
    threshold_pubkey = sum_coms.commitment_to_secret()
    pubshares = [sum_coms.pubshare(i) for i in range(n)]
    dkg_output = DKGOutput(
        None,
        threshold_pubkey.to_bytes_compressed(),
        [pubshare.to_bytes_compressed() for pubshare in pubshares],
    )
    eq_input = t.to_bytes(4, byteorder="big") + sum_coms.to_bytes()
    return cmsg, dkg_output, eq_input
