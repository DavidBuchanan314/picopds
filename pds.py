import asyncio
import logging
import aiohttp_cors
import aiohttp
import dag_cbor
from aiohttp import web
import jwt_monkeypatch as jwt
from typing import Set
import time

from config import DID_PLC, HANDLE, PASSWORD, JWT_ACCESS_SECRET, APPVIEW_SERVER

logging.basicConfig(level=logging.DEBUG)

privkey = open("privkey.pem", "rb").read()
APPVIEW_AUTH = {
	"Authorization": "Bearer " + jwt.encode({
		"iss": DID_PLC,
		"aud": f"did:web:{APPVIEW_SERVER}",
		"exp": int(time.time()) + 60*60*24 # 24h
	}, privkey, algorithm="ES256K")
}


def jwt_access_subject(token: str) -> str:
	try:
		payload = jwt.decode(token, JWT_ACCESS_SECRET, ["HS256"])
	except jwt.PyJWTError:
		raise web.HTTPUnauthorized(text="invalid jwt")
	
	if payload.get("scope") != "com.atproto.access":
		raise web.HTTPUnauthorized(ext="invalid jwt scope")
	
	now = int(time.time())
	if "iat" not in payload or payload["iat"] > now:
		raise web.HTTPUnauthorized(text="invalid jwt: issued in the future")
	
	if "exp" not in payload or payload["exp"] < now:
		raise web.HTTPUnauthorized(text="invalid jwt: expired")
	
	if "sub" not in payload:
		raise web.HTTPUnauthorized(text="invalid jwt: no subject")

	return payload["sub"]

# decorator
def authenticated(handler):
	def authentication_handler(request: web.Request):
		auth = request.headers.getone("Authorization")
		authtype, value = auth.split(" ")
		if authtype != "Bearer":
			raise web.HTTPUnauthorized(text="invalid auth type")
		subject = jwt_access_subject(value)
		if subject != DID_PLC:
			raise web.HTTPUnauthorized(text="invalid auth subject")
		return handler(request)
	return authentication_handler

preferences = {"preferences": []}
firehose_queues: Set[asyncio.Queue] = set()
firehose_queues_lock = asyncio.Lock()

async def firehose_broadcast(msg: bytes):
	async with firehose_queues_lock:  # make sure it can't change while we iterate
		for queue in firehose_queues:
			await queue.put(msg)

async def hello(request: web.Request):
	event = dag_cbor.encode({"t": "#info", "op": 1}) + dag_cbor.encode({"name": "retr0.id/info", "message": "Hello, world!"})
	await firehose_broadcast(event)
	return web.Response(text="Hello, world!")


async def server_describe_server(request: web.Request):
	return web.json_response({
		"availableUserDomains": []
	})

async def server_create_session(request: web.Request):
	json = await request.json()

	if json.get("identifier") != HANDLE or json.get("password") != PASSWORD:
		raise web.HTTPUnauthorized(text="invalid username or password")
	
	return web.json_response({
		"accessJwt": jwt.encode({
			"scope": "com.atproto.access",
			"sub": DID_PLC,
			"iat": int(time.time()),
			"exp": int(time.time()) + 60*60*24 # 24h
		}, JWT_ACCESS_SECRET, "HS256"),
		"refreshJwt": "todo",
		"handle": HANDLE,
		"did": DID_PLC
	})

@authenticated
async def server_get_session(request: web.Request):
	return web.json_response({
		"handle": HANDLE,
		"did": DID_PLC,
		"email": "email@example.org",
	})

@authenticated
async def identity_resolve_handle(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/com.atproto.identity.resolveHandle", params=request.query) as r:
		return web.json_response(await r.json(), status=r.status)

async def sync_subscribe_repos(request: web.Request):
	ws = web.WebSocketResponse()
	await ws.prepare(request)

	queue = asyncio.Queue()
	async with firehose_queues_lock:
		firehose_queues.add(queue)

	print("NEW FIREHOSE CLIENT", request.remote, request.forwarded)

	try:
		while True:
			await ws.send_bytes(await queue.get())
	except ConnectionResetError:
		await ws.close()
		return ws
	finally:
		async with firehose_queues_lock:
			firehose_queues.remove(queue)


@authenticated
async def bsky_actor_get_preferences(request: web.Request):
	return web.json_response(preferences)

@authenticated
async def bsky_actor_put_preferences(request: web.Request):
	global preferences

	json = await request.json()
	print(json)
	preferences = json
	return web.json_response({})

@authenticated
async def bsky_actor_search_actors_typeahead(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.actor.searchActorsTypeahead", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_graph_get_lists(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.graph.getLists", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_graph_get_follows(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.graph.getFollows", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_graph_get_followers(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.graph.getFollowers", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_actor_get_profile(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.actor.getProfile", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_timeline(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getTimeline", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_author_feed(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getAuthorFeed", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_actor_feeds(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getActorFeeds", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)


@authenticated
async def bsky_notification_list_notifications(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.notification.listNotifications", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_notification_update_seen(request: web.Request):
	body = await request.json()
	async with client.post(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.notification.updateSeen", params=request.query, json=body, headers=APPVIEW_AUTH) as r:
		return web.Response(body=await r.read(), status=r.status)

@authenticated
async def bsky_get_popular_feeds(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.unspecced.getPopularFeedGenerators", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_feed_generator(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getFeedGenerator", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_feed_generators(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getFeedGenerators", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_post_thread(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getPostThread", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_posts(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getPosts", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_likes(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getLikes", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_feed(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getFeed", params=request.query, headers=APPVIEW_AUTH) as r:
		return web.json_response(await r.json(), status=r.status)

async def main():
	global client

	client = aiohttp.ClientSession()

	
	app = web.Application()
	app.add_routes([
		web.get ("/", hello),
		web.get ("/xrpc/app.bsky.actor.getPreferences", bsky_actor_get_preferences),
		web.post("/xrpc/app.bsky.actor.putPreferences", bsky_actor_put_preferences),
		web.get ("/xrpc/app.bsky.actor.getProfile", bsky_actor_get_profile),
		web.get ("/xrpc/app.bsky.actor.searchActorsTypeahead", bsky_actor_search_actors_typeahead),
		
		web.get ("/xrpc/app.bsky.notification.listNotifications", bsky_notification_list_notifications),
		web.post("/xrpc/app.bsky.notification.updateSeen", bsky_notification_update_seen),

		web.get ("/xrpc/app.bsky.graph.getLists", bsky_graph_get_lists),
		web.get ("/xrpc/app.bsky.graph.getFollows", bsky_graph_get_follows),
		web.get ("/xrpc/app.bsky.graph.getFollowers", bsky_graph_get_followers),

		web.get ("/xrpc/app.bsky.feed.getTimeline", bsky_feed_get_timeline),
		web.get ("/xrpc/app.bsky.feed.getAuthorFeed", bsky_feed_get_author_feed),
		web.get ("/xrpc/app.bsky.feed.getActorFeeds", bsky_feed_get_actor_feeds),
		web.get ("/xrpc/app.bsky.feed.getFeed", bsky_feed_get_feed),
		web.get ("/xrpc/app.bsky.feed.getFeedGenerator", bsky_feed_get_feed_generator),
		web.get ("/xrpc/app.bsky.feed.getFeedGenerators", bsky_feed_get_feed_generators),
		web.get ("/xrpc/app.bsky.feed.getPostThread", bsky_feed_get_post_thread),
		web.get ("/xrpc/app.bsky.feed.getPosts", bsky_feed_get_posts),
		web.get ("/xrpc/app.bsky.feed.getLikes", bsky_feed_get_likes),
		web.get ("/xrpc/app.bsky.unspecced.getPopularFeedGenerators", bsky_get_popular_feeds),

		web.get ("/xrpc/com.atproto.identity.resolveHandle", identity_resolve_handle),
		web.get ("/xrpc/com.atproto.server.describeServer", server_describe_server),
		web.post("/xrpc/com.atproto.server.createSession", server_create_session),
		web.get ("/xrpc/com.atproto.server.getSession", server_get_session),
		web.get ("/xrpc/com.atproto.sync.subscribeRepos", sync_subscribe_repos),
	])

	cors = aiohttp_cors.setup(app, defaults={
		"*": aiohttp_cors.ResourceOptions(
			allow_credentials=True,
			expose_headers="*",
			allow_headers="*"
		)
	})

	for route in app.router.routes():
		cors.add(route)
	
	runner = web.AppRunner(app)
	await runner.setup()
	site = web.TCPSite(runner, host="localhost", port=31337)
	await site.start()

	while True:
		await asyncio.sleep(3600)  # sleep forever

asyncio.run(main())
