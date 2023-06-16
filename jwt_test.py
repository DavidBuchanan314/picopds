import jwt
import time

from config import DID_PLC, APPVIEW_SERVER, JWT_ACCESS_SECRET

privkey = open("privkey.pem", "rb").read()

encoded = jwt.encode({
	"iss": DID_PLC,
	"aud": f"did:web:{APPVIEW_SERVER}",
	"exp": int(time.time()) + 60*60*24 # 24h
}, privkey, algorithm="ES256K")

print(encoded)

# curl -i 'https://api.bsky-sandbox.dev/xrpc/app.bsky.feed.getTimeline?algorithm=reverse-chronological&limit=30' -H "Authorization: Bearer ..."


auth = jwt.encode({
	"scope": "com.atproto.access",
	"sub": DID_PLC,
	"iat": int(time.time()),
	"exp": int(time.time()) + 60*60*24 # 24h
}, JWT_ACCESS_SECRET, "HS256")

print(auth)
