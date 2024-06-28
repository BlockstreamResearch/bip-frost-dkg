from secp256k1ref.util import tagged_hash


BIP_TAG = "BIP DKG: "


def tagged_hash_bip_dkg(tag: str, msg: bytes) -> bytes:
    return tagged_hash(BIP_TAG + tag, msg)


def prf(seed: bytes, tag: str, extra_input: bytes = b"") -> bytes:
    return tagged_hash_bip_dkg(tag, seed + extra_input)


class InvalidContributionError(Exception):
    def __init__(self, participant, error):
        self.participant = participant
        self.contrib = error


class InvalidRecoveryDataError(Exception):
    pass


class DeserializationError(Exception):
    pass


class DuplicateHostpubkeyError(Exception):
    pass


class SessionNotFinalizedError(Exception):
    pass
