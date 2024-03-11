from typing import List, NamedTuple

from secp256k1ref.secp256k1 import GE, G, Scalar

from util import kdf, DeserializationError


class Polynomial(NamedTuple):
    """A scalar polynomial.

    A polynomial f of degree at most t - 1 is represented by a list `coeffs` of
    t coefficients, i.e., f(x) = coeffs[0] + ... + coeffs[t-1] * x^(t-1)."""

    coeffs: List[Scalar]

    def eval(self, x: Scalar) -> Scalar:
        """Evaluate a polynomial at position x."""

        value = Scalar(0)
        # Reverse coefficients to compute evaluation via Horner's method
        for coeff in self.coeffs[::-1]:
            value = value * x + coeff
        return value

    def __call__(self, x: Scalar) -> Scalar:
        return self.eval(x)


class GroupInfo(NamedTuple):
    shared_pk: GE
    individual_pks: List[GE]


class VSSCommitment(NamedTuple):
    ges: List[GE]

    def t(self):
        return len(self.ges)

    def verify(self, signer_idx: int, share: Scalar) -> bool:
        P = share * G
        Q = GE.mul(
            *((pow(signer_idx + 1, j), self.ges[j]) for j in range(0, len(self.ges)))
        )
        return P == Q

    # Returns commitments to the coefficients of f
    def to_bytes(self) -> bytes:
        return b"".join([P.to_bytes_compressed_with_infinity() for P in self.ges])

    def __add__(self, other):
        assert self.t() == other.t()
        return [self.ges[i] + other.ges[i] for i in range(self.t())]

    @staticmethod
    def from_bytes_and_t(b: bytes, t: int):
        if len(b) < 33 * t:
            raise DeserializationError
        ges = [GE.from_bytes_compressed(b[i : i + 33]) for i in range(0, 33 * t, 33)]
        return VSSCommitment(ges)

    def group_info(self, n: int) -> GroupInfo:
        """Returns the shared public key and individual public keys of the participants"""
        pk = self.ges[0]
        participant_public_keys = []
        for signer_idx in range(0, n):
            pk_i = GE.mul(
                *(
                    (pow(signer_idx + 1, j), self.ges[j])
                    for j in range(0, len(self.ges))
                )
            )
            participant_public_keys += [pk_i]
        return GroupInfo(pk, participant_public_keys)


class VSS(NamedTuple):
    f: Polynomial

    @staticmethod
    def generate(seed, t):
        coeffs = [
            Scalar.from_bytes(kdf(seed, "coeffs", i.to_bytes(4, byteorder="big")))
            for i in range(t)
        ]
        return VSS(Polynomial(coeffs))

    def share_for(self, i: int):
        """Return the secret share to be sent to the signer with index i.

        This computes f(i+1)."""
        x = Scalar(i + 1)
        assert x != Scalar(0)  # Ensure we don't compute f(0), which is the secret.
        return self.f(x)

    def shares(self, n: int) -> List[Scalar]:
        """Return the secret shares to be sent to signers with indices 0..n-1.

        This computes [f(1), ..., f(n)]."""
        return [self.share_for(i) for i in range(0, n)]

    def commit(self) -> VSSCommitment:
        ges = []
        for coeff in self.f.coeffs:
            A_i = coeff * G
            ges.append(A_i)
        return VSSCommitment(ges)

    def secret(self):
        return self.f.coeffs[0]
