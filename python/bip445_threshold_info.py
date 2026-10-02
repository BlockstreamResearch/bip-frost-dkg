# The following definitions are copied verbatim from the reference
# implementation of BIP 445, see
# https://github.com/siv2r/bip-frost-signing/blob/ba299badfbe647e670686de75578dd501a627028/python/frost_ref/signing.py
# `validate_threshold_info` implements the ValidateThresholdInfo algorithm,
# which BIP 445 requires the threshold info to pass before signing.
#
# The secp256k1lab imports below expect the vendored copy of secp256k1lab to be
# on sys.path, so import this module only after importing chilldkg_ref.

# ruff: noqa: UP006, UP035, UP045

from typing import List, NamedTuple, NewType, Optional

from secp256k1lab.secp256k1 import GE, Scalar

PlainPk = NewType("PlainPk", bytes)

# Upper bound on the total number of participants n. See the footnote on this
# bound in the BIP text for the security rationale.
MAX_PARTICIPANTS = 128


def has_duplicates(lst: List[int]) -> bool:
    return len(set(lst)) != len(lst)


def derive_pubshare_at(ids: List[int], pubshares: List[GE], x: int) -> GE:
    assert len(ids) == len(pubshares)
    assert not has_duplicates(ids)
    Q = GE()
    for id_i, X_i in zip(ids, pubshares):
        assert 0 <= id_i < 2**32
        num = Scalar(1)
        deno = Scalar(1)
        for id_k in ids:
            if id_k == id_i:
                continue
            num *= Scalar(x - id_k)
            deno *= Scalar(id_i - id_k)
        Q += (num / deno) * X_i
    return Q  # can be infinity


def derive_thresh_pubkey(ids: List[int], pubshares: List[GE]) -> PlainPk:
    # derive_pubshare_at evaluates in identifier space. Identifiers are 0-based,
    # so participant id sits at polynomial x-coordinate id + 1, and the secret,
    # the constant term at x-coordinate 0, is equal to the identifier -1.
    Q = derive_pubshare_at(ids, pubshares, -1)
    if Q.infinity:
        raise ValueError("The threshold public key must not be the point at infinity.")
    return PlainPk(Q.to_bytes_compressed())


class ThresholdInfo(NamedTuple):
    t: int
    thresh_pk: PlainPk
    # List of length n, where the i-th entry belongs to the participant
    # with id = i. A `None` entry means the participant's public share
    # is unavailable.
    pubshares: List[Optional[PlainPk]]


def validate_threshold_info(info: ThresholdInfo) -> None:
    t, thresh_pk, pubshares = info
    n = len(pubshares)

    if not (1 <= t <= n):
        raise ValueError("The threshold must be 1 <= t <= n.")
    if n > MAX_PARTICIPANTS:
        raise ValueError(f"The number of participants must be n <= {MAX_PARTICIPANTS}.")

    # 1. Validate the threshold public key
    # deserializing before interpolating ensures serialization failures
    # are caught before cryptographic inconsistencies.
    try:
        GE.from_bytes_compressed(thresh_pk)
    except ValueError:
        raise ValueError("The thresh_pk is not a valid point.")

    # 2. Extract and parse present public shares
    parsed_shares = []
    for i, pubshare_bytes in enumerate(pubshares):
        if pubshare_bytes is None:
            continue
        try:
            point = GE.from_bytes_compressed(pubshare_bytes)
            parsed_shares.append((i, point))
        except ValueError:
            raise ValueError(f"The pubshare at index {i} is not a valid point.")

    if len(parsed_shares) < t:
        raise ValueError("At least t pubshares must be present.")

    # 3. Establish the base set for polynomial interpolation
    base_ids = [i for i, _ in parsed_shares[:t]]
    base_points = [point for _, point in parsed_shares[:t]]

    # 3.1 Ensure all pubshares shares lie on the same polynomial
    for i, point in parsed_shares[t:]:
        if derive_pubshare_at(base_ids, base_points, i) != point:
            raise ValueError(
                "The provided key material is incorrect: the public shares do not lie on a single polynomial."
            )
    # 3.2 Ensure the derived threshold key matches the provided one
    if derive_thresh_pubkey(base_ids, base_points) != thresh_pk:
        raise ValueError(
            "The provided key material is incorrect: the public shares do not match the threshold public key."
        )
