from __future__ import annotations

from typing import List, NamedTuple, NewType, Tuple, Optional, NoReturn

from secp256k1lab.bip340 import schnorr_sign, schnorr_verify
from secp256k1lab.secp256k1 import GE, Scalar
from .util import (
    BIP_TAG,
    FaultyParticipantOrCoordinatorError,
    FaultyCoordinatorError,
    UnknownFaultyParticipantOrCoordinatorError,
    MsgParseError,
    ParticipantMsgParseError,
    CoordinatorMsgParseError,
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


def pop_prove(seckey: bytes, idx: int, aux_rand: bytes) -> Pop:
    sig = schnorr_sign(pop_msg(idx), seckey, aux_rand=aux_rand, tag_prefix=POP_MSG_TAG)
    return Pop(sig)


def pop_verify(pop: Pop, pubkey: bytes, idx: int) -> bool:
    return schnorr_verify(pop_msg(idx), pubkey, pop, tag_prefix=POP_MSG_TAG)


###
### Messages
###


class ParticipantMsg(NamedTuple):
    com: VSSCommitment
    pop: Pop

    def to_bytes(self) -> bytes:
        return self.com.to_bytes() + self.pop

    @staticmethod
    def from_bytes(b: bytes, t: int) -> ParticipantMsg:
        rest = b

        # Read com (33*t bytes)
        if len(rest) < 33 * t:
            raise MsgParseError("missing VSS commitment")
        try:
            com, rest = (
                VSSCommitment.from_bytes_and_t(rest[: 33 * t], t),
                rest[33 * t :],
            )
        except ValueError as e:
            raise MsgParseError("invalid VSS commitment") from e

        # Read pop (64 bytes)
        if len(rest) < 64:
            raise MsgParseError("missing proof of possession")
        pop, rest = Pop(rest[:64]), rest[64:]

        if len(rest) != 0:
            raise MsgParseError("incorrect input bytes length")
        return ParticipantMsg(com, pop)


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

    @staticmethod
    def from_bytes(b: bytes, t: int, n: int) -> CoordinatorMsg:
        rest = b

        # Read coms_to_secrets (33*n bytes)
        if len(rest) < 33 * n:
            raise MsgParseError("missing commitments to secrets")
        try:
            coms_to_secrets, rest = (
                [
                    GE.from_bytes_compressed_with_infinity(rest[i : i + 33])
                    for i in range(0, 33 * n, 33)
                ],
                rest[33 * n :],
            )
        except ValueError as e:
            raise MsgParseError("invalid commitment to secret") from e

        # Read sum_coms_to_nonconst_terms (33*(t-1) bytes)
        if len(rest) < 33 * (t - 1):
            raise MsgParseError("missing sum commitments to non-constant terms")
        try:
            sum_coms_to_nonconst_terms, rest = (
                [
                    GE.from_bytes_compressed_with_infinity(rest[i : i + 33])
                    for i in range(0, 33 * (t - 1), 33)
                ],
                rest[33 * (t - 1) :],
            )
        except ValueError as e:
            raise MsgParseError("invalid sum commitment to non-constant term") from e

        # Read pops (64*n bytes)
        if len(rest) < 64 * n:
            raise MsgParseError("missing proofs of possession")
        pops = [Pop(rest[i : i + 64]) for i in range(0, 64 * n, 64)]
        rest = rest[64 * n :]

        if len(rest) != 0:
            raise MsgParseError("incorrect input bytes length")
        return CoordinatorMsg(coms_to_secrets, sum_coms_to_nonconst_terms, pops)


class CoordinatorInvestigationMsg(NamedTuple):
    partial_pubshares: List[GE]

    def to_bytes(self) -> bytes:
        return b"".join(
            [P.to_bytes_compressed_with_infinity() for P in self.partial_pubshares]
        )

    @staticmethod
    def from_bytes(b: bytes, n: int) -> CoordinatorInvestigationMsg:
        rest = b

        # Read partial_pubshares (33*n bytes)
        if len(rest) < 33 * n:
            raise MsgParseError("missing partial pubshares")
        try:
            partial_pubshares, rest = (
                [
                    GE.from_bytes_compressed_with_infinity(rest[i : i + 33])
                    for i in range(0, 33 * n, 33)
                ],
                rest[33 * n :],
            )
        except ValueError as e:
            raise MsgParseError("invalid partial pubshare") from e

        if len(rest) != 0:
            raise MsgParseError("incorrect input bytes length")
        return CoordinatorInvestigationMsg(partial_pubshares)


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


class ParticipantInvestigationData(NamedTuple):
    n: int
    idx: int
    secshare: Scalar
    pubshare: GE


# To keep the algorithms of SimplPedPop and EncPedPop purely non-interactive
# computations, we omit explicit invocations of an interactive equality check
# protocol. ChillDKG will take care of invoking the equality check protocol.


def participant_step1(
    seed: bytes, t: int, n: int, idx: int, aux_rand: bytes
) -> Tuple[
    ParticipantState,
    bytes,
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
    if len(aux_rand) != 32:
        raise ValueError

    vss = VSS.generate(seed, t)  # OverflowError if t >= 2**32
    partial_secshares_from_me = vss.secshares(n)
    pop = pop_prove(vss.secret().to_bytes(), idx, aux_rand)

    com = vss.commit()
    com_to_secret = com.commitment_to_secret()
    msg = ParticipantMsg(com, pop).to_bytes()
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
    cmsg: bytes,
    secshare: Scalar,
) -> Tuple[DKGOutput, bytes]:
    t, n, idx, com_to_secret = state
    try:
        cmsg_parsed = CoordinatorMsg.from_bytes(cmsg, t, n)
    except MsgParseError as e:
        raise CoordinatorMsgParseError(*e.args) from e
    coms_to_secrets, sum_coms_to_nonconst_terms, pops = cmsg_parsed

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
    # Verifying the tweaked secshare against the tweaked pubshare is equivalent
    # to verifying the untweaked secshare against the untweaked pubshare, but
    # avoids computing the untweaked pubshare in the happy path and thereby
    # moves a group addition to the error path.
    sum_coms_tweaked, tweak, pubtweak = sum_coms.invalid_taproot_commit()
    pubshare_tweaked = sum_coms_tweaked.pubshare(idx)
    secshare_tweaked = secshare + tweak
    if not VSSCommitment.verify_secshare(secshare_tweaked, pubshare_tweaked):
        pubshare = pubshare_tweaked - pubtweak
        raise UnknownFaultyParticipantOrCoordinatorError(
            ParticipantInvestigationData(n, idx, secshare, pubshare),
            "Received invalid secshare, "
            "consider investigation procedure to determine faulty party",
        )

    threshold_pubkey = sum_coms_tweaked.commitment_to_secret()
    pubshares = [
        sum_coms_tweaked.pubshare(i)
        if i != idx
        else pubshare_tweaked  # We have computed our own pubshare already.
        for i in range(n)
    ]
    dkg_output = DKGOutput(
        secshare_tweaked.to_bytes(),
        threshold_pubkey.to_bytes_compressed(),
        [pubshare.to_bytes_compressed() for pubshare in pubshares],
    )
    eq_input = t.to_bytes(4, byteorder="big") + sum_coms.to_bytes()
    return dkg_output, eq_input


def participant_investigate(
    error: UnknownFaultyParticipantOrCoordinatorError,
    cinv: bytes,
    partial_secshares: List[Scalar],
) -> NoReturn:
    n, idx, secshare, pubshare = error.inv_data
    if len(partial_secshares) != n:
        raise ValueError

    try:
        cinv_parsed = CoordinatorInvestigationMsg.from_bytes(cinv, n)
    except MsgParseError as e:
        raise CoordinatorMsgParseError(*e.args) from e
    partial_pubshares = cinv_parsed.partial_pubshares

    if GE.sum(*partial_pubshares) != pubshare:
        raise FaultyCoordinatorError("Sum of partial pubshares not equal to pubshare")

    if Scalar.sum(*partial_secshares) != secshare:
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
    raise RuntimeError(
        "participant_investigate() was called, but all inputs are consistent."
    )


###
### Coordinator
###


def coordinator_step(
    pmsgs: List[bytes], t: int, n: int
) -> Tuple[bytes, DKGOutput, bytes]:
    if len(pmsgs) != n:
        raise ValueError
    pmsgs_parsed = []
    for i, pmsg in enumerate(pmsgs):
        try:
            parsed = ParticipantMsg.from_bytes(pmsg, t)
        except MsgParseError as e:
            raise ParticipantMsgParseError(i, *e.args) from e
        pmsgs_parsed.append(parsed)
    # Sum the commitments to the i-th coefficients for i > 0
    #
    # This procedure corresponds to the one described by Pedersen in Section 5.1
    # of "Non-Interactive and Information-Theoretic Secure Verifiable Secret
    # Sharing". However, we don't sum the commitments to the secrets (i == 0)
    # because they'll be necessary to check the pops.
    coms_to_secrets = [pmsg.com.commitment_to_secret() for pmsg in pmsgs_parsed]
    # But we can sum the commitments to the non-constant terms.
    sum_coms_to_nonconst_terms = [
        GE.sum(*(pmsg.com.commitment_to_nonconst_terms()[j] for pmsg in pmsgs_parsed))
        for j in range(t - 1)
    ]
    pops = [pmsg.pop for pmsg in pmsgs_parsed]
    cmsg = CoordinatorMsg(coms_to_secrets, sum_coms_to_nonconst_terms, pops).to_bytes()

    sum_coms = assemble_sum_coms(coms_to_secrets, sum_coms_to_nonconst_terms)
    sum_coms_tweaked, _, _ = sum_coms.invalid_taproot_commit()
    threshold_pubkey = sum_coms_tweaked.commitment_to_secret()
    pubshares = [sum_coms_tweaked.pubshare(i) for i in range(n)]

    dkg_output = DKGOutput(
        None,
        threshold_pubkey.to_bytes_compressed(),
        [pubshare.to_bytes_compressed() for pubshare in pubshares],
    )
    eq_input = t.to_bytes(4, byteorder="big") + sum_coms.to_bytes()
    return cmsg, dkg_output, eq_input


def coordinator_investigate(pmsgs: List[bytes], t: int) -> List[bytes]:
    n = len(pmsgs)
    pmsgs_parsed = [ParticipantMsg.from_bytes(pmsg, t) for pmsg in pmsgs]
    all_partial_pubshares = [
        [pmsg.com.pubshare(i) for pmsg in pmsgs_parsed] for i in range(n)
    ]
    return [
        CoordinatorInvestigationMsg(all_partial_pubshares[i]).to_bytes()
        for i in range(n)
    ]
