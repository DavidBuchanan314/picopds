"""
extremely cursed: monkeypatch pyjwt to always produce low-s secp256k1 ECDSA signatures
"""

from jwt import *
from jwt import algorithms
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

SECP256K1_N = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141

orig_der_to_raw_signature = algorithms.der_to_raw_signature

def low_s_patched_der_to_raw_signature(der_sig: bytes, curve: ec.EllipticCurve) -> bytes:
	if isinstance(curve, ec.SECP256K1):
		r, s = decode_dss_signature(der_sig)
		if s > SECP256K1_N // 2:
			s = SECP256K1_N - s
		der_sig = encode_dss_signature(r, s)
	return orig_der_to_raw_signature(der_sig, curve)

algorithms.der_to_raw_signature = low_s_patched_der_to_raw_signature
