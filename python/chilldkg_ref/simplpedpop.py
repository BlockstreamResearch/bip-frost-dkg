from secrets import token_bytes as random_bytes
from typing import List, NamedTuple, NewType, Tuple, Optional

from secp256k1ref.bip340 import schnorr_sign, schnorr_verify
from secp256k1ref.secp256k1 import GE, Scalar
from .util import BIP_TAG, InvalidContributionError
from .vss import VSS, VSSCommitment, VSSVerifyError


###
### Proofs of possession (pops)
###


Pop = NewType("Pop", bytes)

POP_MSG_TAG = BIP_TAG + "pop message"


def pop_msg(idx: int):
    return idx.to_bytes(4, byteorder="big")


def pop_prove(seckey, idx, aux_rand: bytes = 32 * b"\x00"):
    sig = schnorr_sign(
        pop_msg(idx), seckey, aux_rand=random_bytes(32), challenge_tag=POP_MSG_TAG
    )
    return Pop(sig)


def pop_verify(pop: Pop, pubkey: bytes, idx: int):
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
    secshare: Optional[Scalar]  # None for coordinator
    threshold_pubkey: GE
    pubshares: List[GE]


def assemble_sum_coms(
    coms_to_secrets: List[GE], sum_coms_to_nonconst_terms: List[GE], n: int
) -> VSSCommitment:
    # Sum the commitments to the secrets
    return VSSCommitment(
        [GE.sum(*(coms_to_secrets[i] for i in range(n)))] + sum_coms_to_nonconst_terms
    )


def common_dkg_output(com, n: int) -> Tuple[GE, List[GE]]:
    # Derive the common parts of the DKG output from the sum of all VSS commitments
    #
    # The common parts are the threshold public key and the individual public shares of
    # all participants.
    threshold_pubkey = com.ges[0]
    pubshares = []
    for i in range(0, n):
        # TODO The following computation is the major part of com.verify(i, ...),
        # which we have already computed for i. We should 1) extract the major part of
        # VSSCommitment.verify into a separate method, and 2) avoid that we're computing
        # it twice here.
        pk_i = GE.batch_mul(*(((i + 1) ** j, com.ges[j]) for j in range(0, com.t())))
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


# To keep the algorithms of SimplPedPop and EncPedPop purely non-interactive
# computations, we omit explicit invocations of an interactive equality check
# protocol. ChillDKG will take care of invoking the equality check protocol.


def participant_step1(
    seed: bytes, t: int, n: int, participant_idx: int
) -> Tuple[ParticipantState, ParticipantMsg, List[Scalar]]:
    assert t < 2 ** (4 * 8)
    assert participant_idx < 2 ** (4 * 8)

    vss = VSS.generate(seed, t)
    shares = vss.shares(n)
    pop = pop_prove(vss.secret().to_bytes(), participant_idx)

    com = vss.commit()
    com_to_secret = com.commitment_to_secret()
    msg = ParticipantMsg(com, pop)
    state = ParticipantState(t, n, participant_idx, com_to_secret)
    return state, msg, shares


def participant_step2(
    state: ParticipantState,
    cmsg: CoordinatorMsg,
    secshare: Scalar,
) -> Tuple[DKGOutput, bytes]:
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
    sum_coms = assemble_sum_coms(coms_to_secrets, sum_coms_to_nonconst_terms, n)
    if not sum_coms.verify(idx, secshare):
        raise VSSVerifyError()
    threshold_pubkey, pubshares = common_dkg_output(sum_coms, n)
    eq_input = t.to_bytes(4, byteorder="big") + sum_coms.to_bytes()
    return DKGOutput(secshare, threshold_pubkey, pubshares), eq_input


###
### Coordinator
###


def coordinator_step(
    pmsgs: List[ParticipantMsg], t: int, n: int
) -> Tuple[CoordinatorMsg, DKGOutput, bytes]:
    # Sum the commitments to the i-th coefficients for i > 0
    #
    # This procedure is introduced by Pedersen in Section 5.1 of
    # 'Non-Interactive and Information-Theoretic Secure Verifiable Secret
    # Sharing'.

    # We cannot sum the commitments to the secrets (i == 0) because they'll be
    # necessary to check the pops.
    coms_to_secrets = [pmsg.com.commitment_to_secret() for pmsg in pmsgs]

    # But we can sum the commitments to the non-constant terms.
    sum_coms_to_nonconst_terms = [
        GE.sum(*(pmsg.com.commitment_to_nonconst_terms()[j] for pmsg in pmsgs))
        for j in range(0, t - 1)
    ]
    pops = [pmsg.pop for pmsg in pmsgs]
    sum_coms = assemble_sum_coms(coms_to_secrets, sum_coms_to_nonconst_terms, n)
    threshold_pubkey, pubshares = common_dkg_output(sum_coms, n)
    dkg_output = DKGOutput(None, threshold_pubkey, pubshares)
    eq_input = t.to_bytes(4, byteorder="big") + sum_coms.to_bytes()
    return (
        CoordinatorMsg(coms_to_secrets, sum_coms_to_nonconst_terms, pops),
        dkg_output,
        eq_input,
    )
