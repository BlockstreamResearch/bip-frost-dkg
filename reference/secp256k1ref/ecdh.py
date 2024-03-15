import hashlib

from .secp256k1 import GE, Scalar


def ecdh_raw(my_seckey: bytes, their_pubkey: bytes):
    x = Scalar.from_bytes(my_seckey)
    assert x != 0
    Y = GE.from_bytes_compressed(their_pubkey)
    Z = x * Y
    assert not Z.infinity
    return Z


def ecdh_libsecp256k1(my_seckey: bytes, their_pubkey: bytes):
    Z = ecdh_raw(my_seckey, their_pubkey)
    return hashlib.sha256(Z.to_bytes_compressed().digest())
