import jwt
import time

from config import DID_PLC, APPVIEW_SERVER

privkey = open("privkey.pem", "rb").read()

encoded = jwt.encode({
	"iss": DID_PLC,
	"aud": f"did:web:{APPVIEW_SERVER}",
	"exp": int(time.time()) + 60*60*24 # 24h
}, privkey, algorithm="ES256K")

print(encoded)

# curl -i 'https://api.bsky-sandbox.dev/xrpc/app.bsky.feed.getTimeline?algorithm=reverse-chronological&limit=30' -H "Authorization: Bearer ..."
