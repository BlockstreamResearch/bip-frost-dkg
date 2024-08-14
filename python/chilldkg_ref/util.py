from typing import Optional

from secp256k1proto.util import tagged_hash


BIP_TAG = "BIP DKG/"


def tagged_hash_bip_dkg(tag: str, msg: bytes) -> bytes:
    return tagged_hash(BIP_TAG + tag, msg)


def prf(seed: bytes, tag: str, extra_input: bytes = b"") -> bytes:
    return tagged_hash_bip_dkg(tag, seed + extra_input)


class SecretKeyError(ValueError):
    pass


class ThresholdError(ValueError):
    pass


class InvalidContributionError(Exception):
    def __init__(self, participant: Optional[int], error: str) -> None:
        self.participant = participant
        self.contrib = error
