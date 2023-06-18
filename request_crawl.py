import requests
import jwt_monkeypatch as jwt
import time

from config import DID_PLC, BGS_SERVER, PDS_SERVER

privkey = open("privkey.pem", "rb").read()
auth = jwt.encode({
	"iss": DID_PLC,
	"aud": f"did:web:{BGS_SERVER}",
	"exp": int(time.time()) + 60*60 # 1h
}, privkey, algorithm="ES256K")

# TODO: complain that this really ought to be a POST
r = requests.get(
	f"https://{BGS_SERVER}/xrpc/com.atproto.sync.requestCrawl",
	params={"hostname": PDS_SERVER},
	headers={"Authorization": "Bearer " + auth}
)
print(r.ok)
print(r.content)
