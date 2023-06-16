from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import multiformats
import dag_cbor
import hashlib
import base64
import requests
import json


HANDLE = "david.dev.retr0.id"
PDS_URL = "https://pds.dev.retr0.id"
PLC_SERVER = "https://plc.bsky-sandbox.dev"


def create_did_web_pubkey(pubkey: ec.EllipticCurvePublicKey):
	assert(type(pubkey.curve) is ec.SECP256K1)
	compressed_public_bytes = pubkey.public_bytes(
		serialization.Encoding.X962,
		serialization.PublicFormat.CompressedPoint
	)
	return "did:key:" + multiformats.multibase.encode(
		multiformats.multicodec.wrap("secp256k1-pub", compressed_public_bytes),
		"base58btc"
	)




privkey = ec.generate_private_key(ec.SECP256K1())
pubkey = privkey.public_key()

with open("privkey.pem", "wb") as keyfile:
	keyfile.write(privkey.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	))

#print(serialization.load_pem_private_key(open("privkey.pem", "rb").read(), password=None))

genesis = {
	"type": "plc_operation",
	"rotationKeys": [
		create_did_web_pubkey(pubkey),
	],
	"verificationMethods": {
		"atproto": create_did_web_pubkey(pubkey), #XXX should really be separate from rotationKeys
	},
	"alsoKnownAs": [
		"at://" + HANDLE
	],
	"services": {
		"atproto_pds": {
			"type": "AtprotoPersonalDataServer",
			"endpoint": PDS_URL
		}
	},
	"prev": None,
}

genesis_bytes = dag_cbor.encode(genesis)
r, s = decode_dss_signature(privkey.sign(genesis_bytes, ec.ECDSA(hashes.SHA256())))

# apply low-s malleability mitigation
SECP256K1_N = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
if s > SECP256K1_N // 2: # XXX there might be an off-by-one here lol
	s = SECP256K1_N - s

signature = base64.urlsafe_b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode().strip("=")
signed_genesis = genesis | {"sig": signature}
signed_genesis_bytes = dag_cbor.encode(signed_genesis)

plc = "did:plc:" + base64.b32encode(hashlib.sha256(signed_genesis_bytes).digest())[:24].lower().decode()

print(json.dumps(signed_genesis, indent="  "))
print("Created DID:", plc)

print("Publishing...")

plc_url = PLC_SERVER + "/" + plc
r = requests.post(plc_url, json=signed_genesis)
print(r, r.content)
assert(r.ok)

print("Your PLC should now be live at", plc_url)
