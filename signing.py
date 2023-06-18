
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

SECP256K1_N = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141

def raw_sign(privkey: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
	r, s = decode_dss_signature(privkey.sign(data, ec.ECDSA(hashes.SHA256())))

	# apply low-s malleability mitigation
	if s > SECP256K1_N // 2:
		s = SECP256K1_N - s

	signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
	return signature
