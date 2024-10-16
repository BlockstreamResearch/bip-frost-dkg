from secrets import token_bytes as random_bytes
from typing import List, NamedTuple, NewType, Tuple, Optional, NoReturn

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


class SecshareSumError(ValueError):
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
    seed: bytes, t: int, n: int, idx: int
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
# participant_step2() from the partial_secshares returned by all participants'
# participant_step1().
#
# This computation cannot be done entirely by the SimplPedPop coordinator
# because it involves secret shares. In a pure run of SimplPedPop where secret
# shares are sent via external secure channels (i.e., EncPedPop is not used),
# each participant needs to run this to prepare their participant_step2().
#
# In EncPedPop, the coordinator will know the encrypted secret shares and will
# take care of this preparation by exploiting the homomorphic property of the
# encryption.
# FIXME rename in previous commit
def participant_step2_prepare_secret_side_inputs(
    partial_secshares: List[Scalar],
) -> Scalar:
    secshare: Scalar = Scalar.sum(*partial_secshares)
    return secshare


def participant_step2(
    state: ParticipantState,
    cmsg: CoordinatorMsg,
    secshare: Scalar,
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
    pubshare = sum_coms.pubshare(idx)

    if not VSSCommitment.verify_secshare(secshare, pubshare):
        raise FaultyParticipantError(
            None,
            "Received invalid secshare, consider running participant_blame()",
        )

    pubshares = [sum_coms.pubshare(i) if i != idx else pubshare for i in range(n)]
    dkg_output = DKGOutput(
        secshare.to_bytes(),
        threshold_pubkey.to_bytes_compressed(),
        [pubshare.to_bytes_compressed() for pubshare in pubshares],
    )
    eq_input = t.to_bytes(4, byteorder="big") + sum_coms.to_bytes()
    return dkg_output, eq_input


def participant_blame(
    state: ParticipantState,
    secshare: Scalar,
    partial_secshares: List[Scalar],
    blame_rec: BlameRecord,
) -> NoReturn:
    _, n, idx, _ = state
    partial_pubshares = blame_rec.partial_pubshares

    if Scalar.sum(*partial_secshares) != secshare:
        raise SecshareSumError("Sum of partial secshares not equal to secshare")

    for i in range(n):
        if not VSSCommitment.verify_secshare(
            partial_secshares[i], partial_pubshares[i]
        ):
            if i != idx:
                raise FaultyParticipantError(
                    i, "Participant sent invalid partial secshare"
                )
            else:
                # We are not faulty, so the coordinator must be.
                raise FaultyCoordinatorError(
                    "Coordinator fiddled with the share from me to myself"
                )

    # We now know:
    #  - The sum of the partial secshares is equal to the secshare.
    #  - Every partial secshare matches its corresponding partial pubshare.
    #  - The sum of the partial pubshares is not equal to the pubshare (because
    #    the caller shouldn't have called us otherwise).
    # Therefore, the sum of the partial pubshares is not equal to the pubshare,
    # and this is the coordinator's fault.
    raise FaultyCoordinatorError(
        "Sum of partial pubshares not equal to pubshare (or participant_blame() "
        "was called even though participant_step2() was successful)"
    )


###
### Coordinator
###


def coordinator_step(
    pmsgs: List[ParticipantMsg], t: int, n: int
) -> Tuple[CoordinatorMsg, DKGOutput, bytes]:
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

    dkg_output = DKGOutput(
        None,
        threshold_pubkey.to_bytes_compressed(),
        [pubshare.to_bytes_compressed() for pubshare in pubshares],
    )
    eq_input = t.to_bytes(4, byteorder="big") + sum_coms.to_bytes()
    return cmsg, dkg_output, eq_input


def coordinator_blame(pmsgs: List[ParticipantMsg]) -> List[BlameRecord]:
    n = len(pmsgs)
    all_partial_pubshares = [[pmsg.com.pubshare(i) for pmsg in pmsgs] for i in range(n)]
    return [BlameRecord(all_partial_pubshares[i]) for i in range(n)]
