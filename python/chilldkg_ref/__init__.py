from pathlib import Path
import sys


__all__ = ["chilldkg"]

# Prefer the vendored copy of secp256k1lab.
sys.path.insert(0, str(Path(__file__).parent / "../secp256k1lab/src"))
