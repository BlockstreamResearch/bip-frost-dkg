from __future__ import annotations

from typing import List

from secp256k1ref.secp256k1 import GE, G, Scalar

from .util import prf, DeserializationError


class Polynomial:
    # A scalar polynomial.
    #
    # A polynomial f of degree at most t - 1 is represented by a list `coeffs`
    # of t coefficients, i.e., f(x) = coeffs[0] + ... + coeffs[t-1] *
    # x^(t-1)."""
    coeffs: List[Scalar]

    def __init__(self, coeffs: List[Scalar]) -> None:
        self.coeffs = coeffs

    def eval(self, x: Scalar) -> Scalar:
        # Evaluate a polynomial at position x.

        value = Scalar(0)
        # Reverse coefficients to compute evaluation via Horner's method
        for coeff in self.coeffs[::-1]:
            value = value * x + coeff
        return value

    def __call__(self, x: Scalar) -> Scalar:
        return self.eval(x)


class VSSCommitment:
    ges: List[GE]

    def __init__(self, ges: List[GE]) -> None:
        self.ges = ges

    def t(self) -> int:
        return len(self.ges)

    def pubshare(self, i: int) -> GE:
        pubshare: GE = GE.batch_mul(
            *(((i + 1) ** j, self.ges[j]) for j in range(0, len(self.ges)))
        )
        return pubshare

    @staticmethod
    def verify_secshare(secshare: Scalar, pubshare: GE) -> bool:
        # The caller needs to provide the correct pubshare(i)
        actual = secshare * G
        valid: bool = actual == pubshare
        return valid

    def to_bytes(self) -> bytes:
        # Return commitments to the coefficients of f.
        return b"".join([ge.to_bytes_compressed_with_infinity() for ge in self.ges])

    def __add__(self, other: VSSCommitment) -> VSSCommitment:
        assert self.t() == other.t()
        return VSSCommitment([self.ges[i] + other.ges[i] for i in range(self.t())])

    @staticmethod
    def from_bytes_and_t(b: bytes, t: int) -> VSSCommitment:
        if len(b) != 33 * t:
            raise DeserializationError
        ges = [GE.from_bytes_compressed(b[i : i + 33]) for i in range(0, 33 * t, 33)]
        return VSSCommitment(ges)

    def commitment_to_secret(self) -> GE:
        return self.ges[0]

    def commitment_to_nonconst_terms(self) -> List[GE]:
        return self.ges[1 : self.t()]


class VSS:
    f: Polynomial

    def __init__(self, f: Polynomial) -> None:
        self.f = f

    @staticmethod
    def generate(seed: bytes, t: int) -> VSS:
        coeffs = [
            Scalar.from_bytes(prf(seed, "vss coeffs", i.to_bytes(4, byteorder="big")))
            for i in range(t)
        ]
        return VSS(Polynomial(coeffs))

    def secshare_for(self, i: int) -> Scalar:
        # Return the secret share for the participant with index i.
        #
        # This computes f(i+1).

        x = Scalar(i + 1)
        # Ensure we don't compute f(0), which is the secret.
        assert x != Scalar(0)
        return self.f(x)

    def secshares(self, n: int) -> List[Scalar]:
        # Return the secret shares for the participants with indices 0..n-1.
        #
        # This computes [f(1), ..., f(n)].
        return [self.secshare_for(i) for i in range(0, n)]

    def commit(self) -> VSSCommitment:
        return VSSCommitment([c * G for c in self.f.coeffs])

    def secret(self) -> Scalar:
        # Return the secret to be shared.
        #
        # This computes f(0).
        return self.f.coeffs[0]
