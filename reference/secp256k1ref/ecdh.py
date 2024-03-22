import hashlib

from .secp256k1 import GE, Scalar


def ecdh_raw(seckey: bytes, pubkey: bytes):
    """TODO"""
    x = Scalar.from_bytes(seckey)
    assert x != 0
    Y = GE.from_bytes_compressed(pubkey)
    Z = x * Y
    assert not Z.infinity
    return Z


def ecdh_libsecp256k1(seckey: bytes, pubkey: bytes):
    """TODO"""
    Z = ecdh_raw(seckey, pubkey)
    return hashlib.sha256(Z.to_bytes_compressed().digest())
