from secrets import token_bytes as random_bytes
from typing import List, NamedTuple, NewType, Tuple, Optional, NoReturn

from secp256k1proto.bip340 import schnorr_sign, schnorr_verify
from secp256k1proto.secp256k1 import G, GE, Scalar
from .util import (
    BIP_TAG,
    FaultyParticipantOrCoordinatorError,
    FaultyCoordinatorError,
    UnknownFaultyParticipantOrCoordinatorError,
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


class CoordinatorBlameMsg(NamedTuple):
    partial_pubshares: List[GE]


###
### Other common definitions
###


class DKGOutput(NamedTuple):
    secshare: Optional[bytes]  # None for coordinator
    threshold_pubkey: bytes
    pubshares: List[bytes]


def assemble_sum_coms(
    coms_to_secrets: List[GE], sum_coms_to_nonconst_terms: List[GE]
) -> VSSCommitment:
    # Sum the commitments to the secrets
    return VSSCommitment(
        [GE.sum(*(c for c in coms_to_secrets))] + sum_coms_to_nonconst_terms
    )


###
### Participant
###


class ParticipantState(NamedTuple):
    t: int
    n: int
    idx: int
    com_to_secret: GE


class ParticipantBlameState(NamedTuple):
    n: int
    idx: int
    secshare: Scalar
    secshare_tweak: Scalar
    pubshare: GE


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
    # the function participant_step2_prepare_secshare().
    List[Scalar],
]:
    if t > n:
        raise ValueError
    if idx >= n:
        raise IndexError
    if len(seed) != 32:
        raise ValueError

    vss = VSS.generate(seed, t)  # OverflowError if t >= 2**32
    partial_secshares_from_me = vss.secshares(n)
    pop = pop_prove(vss.secret().to_bytes(), idx)

    com = vss.commit()
    com_to_secret = com.commitment_to_secret()
    msg = ParticipantMsg(com, pop)
    state = ParticipantState(t, n, idx, com_to_secret)
    return state, msg, partial_secshares_from_me


# Helper function to prepare the secshare for participant idx's
# participant_step2() by summing the partial_secshares returned by all
# participants' participant_step1().
#
# In a pure run of SimplPedPop where secret shares are sent via external secure
# channels (i.e., EncPedPop is not used), each participant needs to run this
# function in preparation of their participant_step2(). Since this computation
# involves secret data, it cannot be delegated to the coordinator as opposed to
# other aggregation steps.
#
# If EncPedPop is used instead (as a wrapper of SimplPedPop), the coordinator
# can securely aggregate the encrypted partial secshares into an encrypted
# secshare by exploiting the additively homomorphic property of the encryption.
def participant_step2_prepare_secshare(
    partial_secshares: List[Scalar],
) -> Scalar:
    secshare: Scalar  # REVIEW Work around missing type annotation of Scalar.sum
    secshare = Scalar.sum(*partial_secshares)
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
            raise FaultyParticipantOrCoordinatorError(
                i, "Participant sent invalid commitment"
            )
        # This can be optimized: We serialize the coms_to_secrets[i] here, but
        # schnorr_verify (inside pop_verify) will need to deserialize it again, which
        # involves computing a square root to obtain the y coordinate.
        if not pop_verify(pops[i], coms_to_secrets[i].to_bytes_xonly(), i):
            raise FaultyParticipantOrCoordinatorError(
                i, "Participant sent invalid proof-of-knowledge"
            )
    sum_coms = assemble_sum_coms(coms_to_secrets, sum_coms_to_nonconst_terms)
    sum_coms_tweaked, secshare_tweak = sum_coms.invalid_taproot_commit()
    secshare += secshare_tweak
    threshold_pubkey = sum_coms_tweaked.commitment_to_secret()
    pubshare = sum_coms_tweaked.pubshare(idx)

    if not VSSCommitment.verify_secshare(secshare, pubshare):
        raise UnknownFaultyParticipantOrCoordinatorError(
            ParticipantBlameState(n, idx, secshare, secshare_tweak, pubshare),
            "Received invalid secshare, consider blaming to determine faulty party",
        )

    pubshares = [
        sum_coms_tweaked.pubshare(i) if i != idx else pubshare for i in range(n)
    ]
    dkg_output = DKGOutput(
        secshare.to_bytes(),
        threshold_pubkey.to_bytes_compressed(),
        [pubshare.to_bytes_compressed() for pubshare in pubshares],
    )
    eq_input = t.to_bytes(4, byteorder="big") + sum_coms.to_bytes()
    return dkg_output, eq_input


def participant_blame(
    blame_state: ParticipantBlameState,
    cblame: CoordinatorBlameMsg,
    partial_secshares: List[Scalar],
) -> NoReturn:
    n, idx, secshare, secshare_tweak, pubshare = blame_state
    partial_pubshares = cblame.partial_pubshares

    if GE.sum(*partial_pubshares) + secshare_tweak * G != pubshare:
        raise FaultyCoordinatorError("Sum of partial pubshares not equal to pubshare")

    if Scalar.sum(*partial_secshares) + secshare_tweak != secshare:
        raise SecshareSumError("Sum of partial secshares not equal to secshare")

    for i in range(n):
        if not VSSCommitment.verify_secshare(
            partial_secshares[i], partial_pubshares[i]
        ):
            if i != idx:
                raise FaultyParticipantOrCoordinatorError(
                    i, "Participant sent invalid partial secshare"
                )
            else:
                # We are not faulty, so the coordinator must be.
                raise FaultyCoordinatorError(
                    "Coordinator fiddled with the share from me to myself"
                )

    # We now know:
    #  - The sum of the partial secshares is equal to the secshare.
    #  - The sum of the partial pubshares is equal to the pubshare.
    #  - Every partial secshare matches its corresponding partial pubshare.
    # Hence, the secshare matches the pubshare.
    assert VSSCommitment.verify_secshare(secshare, pubshare)

    # This should never happen (unless the caller fiddled with the inputs).
    raise RuntimeError("participant_blame() was called, but all inputs are consistent.")


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

    sum_coms = assemble_sum_coms(coms_to_secrets, sum_coms_to_nonconst_terms)
    sum_coms_tweaked, secshare_tweak = sum_coms.invalid_taproot_commit()
    threshold_pubkey = sum_coms_tweaked.commitment_to_secret()
    pubshares = [sum_coms_tweaked.pubshare(i) for i in range(n)]

    dkg_output = DKGOutput(
        None,
        threshold_pubkey.to_bytes_compressed(),
        [pubshare.to_bytes_compressed() for pubshare in pubshares],
    )
    eq_input = t.to_bytes(4, byteorder="big") + sum_coms.to_bytes()
    return cmsg, dkg_output, eq_input


def coordinator_blame(pmsgs: List[ParticipantMsg]) -> List[CoordinatorBlameMsg]:
    n = len(pmsgs)
    all_partial_pubshares = [[pmsg.com.pubshare(i) for pmsg in pmsgs] for i in range(n)]
    return [CoordinatorBlameMsg(all_partial_pubshares[i]) for i in range(n)]
