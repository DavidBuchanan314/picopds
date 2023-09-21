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

r = requests.post(
	f"https://{BGS_SERVER}/xrpc/com.atproto.sync.requestCrawl",
	json={"hostname": PDS_SERVER},
	headers={"Authorization": "Bearer " + auth}
)
print(r.ok, r.status_code)
print(r.content)
