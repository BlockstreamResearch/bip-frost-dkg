import os
import sys


__all__ = ["chilldkg"]

# Prefer the vendored copy of secp256k1lab.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../secp256k1lab/src"))
