"""
extremely cursed: monkeypatch pyjwt to always produce low-s secp256k1 ECDSA signatures
"""

from jwt import *
from jwt import algorithms
from cryptography.hazmat.primitives.asymmetric import ec
from signing import apply_low_s_mitigation

orig_der_to_raw_signature = algorithms.der_to_raw_signature

def low_s_patched_der_to_raw_signature(der_sig: bytes, curve: ec.EllipticCurve) -> bytes:
	return orig_der_to_raw_signature(apply_low_s_mitigation(der_sig, curve), curve)

algorithms.der_to_raw_signature = low_s_patched_der_to_raw_signature
