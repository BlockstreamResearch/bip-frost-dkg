from secrets import token_bytes as random_bytes
from typing import List, NamedTuple, NewType, Tuple, Optional, NoReturn, cast

from secp256k1proto.bip340 import schnorr_sign, schnorr_verify
from secp256k1proto.secp256k1 import GE, Scalar
from .util import (
    BIP_TAG,
    SecretKeyError,
    ThresholdError,
    FaultyParticipantError,
    FaultyCoordinatorError,
)
from .vss import VSS, VSSCommitment


###
### Exceptions
###


class InconsistentSecsharesError(ValueError):
    pass


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


class BlameRecord(NamedTuple):
    partial_secshares: List[Scalar]
    partial_pubshares: List[GE]


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
    seed: bytes, t: int, n: int, idx: int, blame: bool = True
) -> Tuple[
    ParticipantState,
    ParticipantMsg,
    # The following return value is a list of n partial secret shares generated
    # by this participant. The item at index i is supposed to be made available
    # to participant i privately, e.g., via an external secure channel. See also
    # the function participant_step2_prepare_secret_side_inputs().
    List[Scalar],
]:
    if t > n:
        raise ThresholdError
    if idx >= n:
        raise IndexError
    if len(seed) != 32:
        raise SecretKeyError

    vss = VSS.generate(seed, t)  # OverflowError if t >= 2**32
    partial_secshares_from_me = vss.secshares(n)
    pop = pop_prove(vss.secret().to_bytes(), idx)

    com = vss.commit()
    com_to_secret = com.commitment_to_secret()
    msg = ParticipantMsg(com, pop)
    state = ParticipantState(t, n, idx, com_to_secret)

    return state, msg, partial_secshares_from_me


# Helper function to prepare the secret side inputs for participant idx's
# participant_step2() from
#  - the list of all partial_secshares[idx] values from participants'
#    participant_step1(), and  # FIXME terms are wrong here
#  - the partial_pubshares list from the coordinator's coordinator_step()
#    (if not blaming, this is a list containing n times None).
#
# This computation cannot be done entirely by the SimplPedPop coordinator
# because it involves secret shares. In a pure run of SimplPedPop where secret
# shares are sent via external secure channels (i.e., EncPedPop is not used),
# each participant needs to run this to prepare their participant_step2().
#
# In EncPedPop, the coordinator will know the encrypted secret shares and will
# take care of this preparation by exploiting the homomorphic property of the
# encryption.
def participant_step2_prepare_secret_side_inputs(
    partial_secshares: List[Scalar], partial_pubshares: List[Optional[GE]]
) -> Tuple[Scalar, Optional[BlameRecord]]:
    ## FIXME take n from state, amend other commit
    n = len(partial_secshares)
    secshare = Scalar.sum(*partial_secshares)
    if not len(partial_secshares) == len(partial_pubshares) == n:
        raise ValueError
    # blame_rec: Optional[BlameRecord]
    if partial_pubshares[0] is not None:
        if not all([p is not None for p in partial_pubshares]):
            raise ValueError
        blame_rec = BlameRecord(partial_secshares, cast(List[GE], partial_pubshares))
    else:
        blame_rec = None
    return secshare, blame_rec


def participant_step2(
    state: ParticipantState,
    cmsg: CoordinatorMsg,
    secshare: Scalar,
    blame_rec: Optional[BlameRecord] = None,
) -> Tuple[DKGOutput, bytes]:
    t, n, idx, com_to_secret = state
    coms_to_secrets, sum_coms_to_nonconst_terms, pops = cmsg

    # TODO Raise FaultyCoordinatorError when deserizaltion yields wrong lengths
    assert len(coms_to_secrets) == n
    assert len(sum_coms_to_nonconst_terms) == t - 1
    assert len(pops) == n

    if coms_to_secrets[idx] != com_to_secret:
        raise FaultyCoordinatorError(
            "Coordinator sent unexpected first group element for local index"
        )

    for i in range(n):
        if i == idx:
            # No need to check our own pop.
            continue
        if coms_to_secrets[i].infinity:
            raise FaultyParticipantError(i, "Participant sent invalid commitment")
        # This can be optimized: We serialize the coms_to_secrets[i] here, but
        # schnorr_verify (inside pop_verify) will need to deserialize it again, which
        # involves computing a square root to obtain the y coordinate.
        if not pop_verify(pops[i], coms_to_secrets[i].to_bytes_xonly(), i):
            raise FaultyParticipantError(
                i, "Participant sent invalid proof-of-knowledge"
            )
    sum_coms = assemble_sum_coms(coms_to_secrets, sum_coms_to_nonconst_terms, n)
    threshold_pubkey = sum_coms.commitment_to_secret()
    pubshares = [sum_coms.pubshare(i) for i in range(n)]

    if not VSSCommitment.verify_secshare(secshare, pubshares[idx]):
        if blame_rec is not None:
            _participant_step2_blame(secshare, pubshares, idx, blame_rec)
        else:
            raise FaultyParticipantError(
                None, "Received invalid secshare, consider rerunning in blame mode"
            )

    dkg_output = DKGOutput(
        secshare.to_bytes(),
        threshold_pubkey.to_bytes_compressed(),
        [pubshare.to_bytes_compressed() for pubshare in pubshares],
    )
    eq_input = t.to_bytes(4, byteorder="big") + sum_coms.to_bytes()
    return dkg_output, eq_input


def _participant_step2_blame(
    secshare: Scalar, pubshares: List[GE], idx: int, blame_rec: BlameRecord
) -> NoReturn:
    partial_secshares, partial_pubshares = blame_rec
    n = len(pubshares)
    if Scalar.sum(*partial_secshares) != secshare:
        raise InconsistentSecsharesError
    # The following check can safely be omitted, because we trust the
    # coordinator for computing the partial_pubshares correctly anyway. Or, in
    # other words, the coordinator can anyway make us blame some innocent
    # participant. We keep it because it may help debugging benign failures.
    if GE.sum(*partial_pubshares) != pubshares[idx]:
        raise FaultyCoordinatorError("Sum of partial pubshares not equal to pubshare")
    for i in range(n):
        if not VSSCommitment.verify_secshare(
            partial_secshares[i], partial_pubshares[i]
        ):
            if i != idx:
                raise FaultyParticipantError(
                    i, "Participant sent invalid partial secshare"
                )
            else:
                # We are not faulty, so it must be the coordinator.
                raise FaultyCoordinatorError(
                    "Coordinator fiddled with the share from me to myself"
                )
    assert False, "unreachable"


###
### Coordinator
###


## FIXME document the last return value. Or can we make it an
## Optional[List[List[GE]]] instead? That's more elegant but the type checker
## didn't like me when I had tried this earlier.
def coordinator_step(
    pmsgs: List[ParticipantMsg], t: int, n: int, blame: bool = True
) -> Tuple[CoordinatorMsg, DKGOutput, bytes, List[List[Optional[GE]]]]:
    # Sum the commitments to the i-th coefficients for i > 0 # FIXME
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
        for j in range(t - 1)
    ]
    pops = [pmsg.pop for pmsg in pmsgs]
    cmsg = CoordinatorMsg(coms_to_secrets, sum_coms_to_nonconst_terms, pops)

    sum_coms = assemble_sum_coms(coms_to_secrets, sum_coms_to_nonconst_terms, n)
    threshold_pubkey = sum_coms.commitment_to_secret()
    pubshares = [sum_coms.pubshare(i) for i in range(n)]

    partial_pubshares: List[List[Optional[GE]]]
    if blame:
        partial_pubshares = [[pmsg.com.pubshare(i) for pmsg in pmsgs] for i in range(n)]
    else:
        partial_pubshares = [[None for pmsg in pmsgs] for i in range(n)]

    dkg_output = DKGOutput(
        None,
        threshold_pubkey.to_bytes_compressed(),
        [pubshare.to_bytes_compressed() for pubshare in pubshares],
    )
    eq_input = t.to_bytes(4, byteorder="big") + sum_coms.to_bytes()
    return cmsg, dkg_output, eq_input, partial_pubshares
