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
from signing import raw_sign

from config import HANDLE, PDS_SERVER, PLC_SERVER

def create_did_pubkey(pubkey: ec.EllipticCurvePublicKey):
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
		create_did_pubkey(pubkey),
	],
	"verificationMethods": {
		"atproto": create_did_pubkey(pubkey), #XXX should really be separate from rotationKeys
	},
	"alsoKnownAs": [
		"at://" + HANDLE
	],
	"services": {
		"atproto_pds": {
			"type": "AtprotoPersonalDataServer",
			"endpoint": "https://" + PDS_SERVER
		}
	},
	"prev": None,
}

genesis_bytes = dag_cbor.encode(genesis)
signature = base64.urlsafe_b64encode(raw_sign(privkey, genesis_bytes)).decode().strip("=")
signed_genesis = genesis | {"sig": signature}
signed_genesis_bytes = dag_cbor.encode(signed_genesis)

plc = "did:plc:" + base64.b32encode(hashlib.sha256(signed_genesis_bytes).digest())[:24].lower().decode()

json_blob = json.dumps(signed_genesis, indent="\t")

with open("did_plc.txt", "w") as logfile:
	print("Created DID:", plc, file=logfile)
	print("", file=logfile)
	print(json_blob, file=logfile)

print(json_blob)
print()
print("Created DID:", plc)


print("Publishing...")

plc_url = "https://" + PLC_SERVER + "/" + plc
r = requests.post(plc_url, json=signed_genesis)
print(r, r.content)
assert(r.ok)

print("Your PLC should now be live at", plc_url)
