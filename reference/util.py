from secp256k1ref.util import tagged_hash


BIP_TAG = "BIP DKG: "


def tagged_hash_bip_dkg(tag: str, msg: bytes) -> bytes:
    return tagged_hash(BIP_TAG + tag, msg)


def kdf(seed: bytes, tag: str, extra_input: bytes = b"") -> bytes:
    # TODO: consider different KDF
    return tagged_hash_bip_dkg(tag + "KDF ", seed + extra_input)


# TODO Document in all functions what exceptions they can raise


class InvalidContributionError(Exception):
    def __init__(self, signer, error):
        self.signer = signer
        self.contrib = error


class InvalidBackupError(Exception):
    pass


class DeserializationError(Exception):
    pass


class DuplicateHostpubkeyError(Exception):
    def __init__(self):
        pass
