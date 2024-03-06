# The following functions were copied from the BIP 327 reference implementation
# https://github.com/bitcoin/bips/blob/master/bip-0327/reference.py

from crypto_bip340 import int_from_bytes
from secp256k1ref.secp256k1 import GE, G
from typing import NewType

PlainPk = NewType("PlainPk", bytes)

# BIP DKG specific functions

# Return the plain public key corresponding to a given secret key
def pubkey_gen_plain(seckey: bytes) -> PlainPk:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= GE.ORDER - 1):
        raise ValueError("The secret key must be an integer in the range 1..n-1.")
    P = d0 * G
    assert not P.infinity
    return PlainPk(P.to_bytes_compressed())
