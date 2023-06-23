from cryptography.hazmat.primitives import serialization
import asyncio
import logging
import aiohttp_cors
import aiohttp
import dag_cbor
from aiohttp import web
import jwt_monkeypatch as jwt
from typing import Set
import time
from repo import Repo
from multiformats import CID
from cachetools import cached, TTLCache

from record_serdes import record_to_json, json_to_record
from config import DID_PLC, HANDLE, PASSWORD, JWT_ACCESS_SECRET, APPVIEW_SERVER

logging.basicConfig(level=logging.DEBUG)

privkey_bytes = open("privkey.pem", "rb").read()
privkey_obj = serialization.load_pem_private_key(privkey_bytes, password=None)

@cached(cache=TTLCache(maxsize=1, ttl=60*60)) # 1h TTL
def get_appview_auth():
	return {
		"Authorization": "Bearer " + jwt.encode({
			"iss": DID_PLC,
			"aud": f"did:web:{APPVIEW_SERVER}",
			"exp": int(time.time()) + 60*60*24 # 24h
		}, privkey_bytes, algorithm="ES256K")
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

firehose_queues: Set[asyncio.Queue] = set()
firehose_queues_lock = asyncio.Lock()
repo = Repo(DID_PLC, "repo.db", privkey_obj)

async def firehose_broadcast(msg: bytes):
	async with firehose_queues_lock:  # make sure it can't change while we iterate
		for queue in firehose_queues:
			await queue.put(msg)

async def hello(request: web.Request):
	return web.Response(text="Hello! This is an ATProto PDS instance, running on https://github.com/DavidBuchanan314/picopds")


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

#TODO: require auth if we can't answer it ourselves
#@authenticated
async def identity_resolve_handle(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/com.atproto.identity.resolveHandle", params=request.query) as r:
		return web.json_response(await r.json(), status=r.status)

async def sync_subscribe_repos(request: web.Request):
	ws = web.WebSocketResponse()
	await ws.prepare(request)

	queue = asyncio.Queue()
	async with firehose_queues_lock:
		firehose_queues.add(queue)

	print("NEW FIREHOSE CLIENT", request.remote, request.headers.get("x-forwarded-for"))

	try:
		while True:
			await ws.send_bytes(await queue.get())
	except ConnectionResetError:
		await ws.close()
		return ws
	finally:
		async with firehose_queues_lock:
			firehose_queues.remove(queue)

async def sync_get_repo(request: web.Request):
	did = request.query["did"]
	assert(did == repo.did)
	return web.Response(body=repo.get_checkout(), content_type="application/vnd.ipld.car")

async def sync_get_checkout(request: web.Request):
	did = request.query["did"]
	assert(did == repo.did)
	commit = request.query.get("commit")
	if commit is not None:
		commit = CID.decode(commit)
	return web.Response(body=repo.get_checkout(commit), content_type="application/vnd.ipld.car")

@authenticated
async def repo_create_record(request: web.Request):
	req = json_to_record(await request.json())
	assert(req["repo"] == DID_PLC)
	collection = req["collection"]
	rkey = req.get("rkey")
	record = req["record"]
	uri, cid, firehose_msg = repo.create_record(collection, record, rkey)
	await firehose_broadcast(firehose_msg)
	return web.json_response({
		"uri": uri,
		"cid": cid.encode("base32")
	})

@authenticated
async def repo_get_record(request: web.Request):
	collection = request.query["collection"]
	repo_did = request.query["repo"]
	rkey = request.query["rkey"]
	if repo_did == repo.did:
		# TODO: return correct error on not found
		uri, cid, value = repo.get_record(collection, rkey)
		return web.json_response(record_to_json({
			"uri": uri,
			"cid": cid.encode("base32"),
			"value": dag_cbor.decode(value)
		}))
	else:
		async with client.get(f"https://{APPVIEW_SERVER}/xrpc/com.atproto.repo.getRecord", params=request.query, headers=get_appview_auth()) as r:
			return web.json_response(await r.json(), status=r.status)

@authenticated
async def repo_upload_blob(request: web.Request):
	mime = request.headers["content-type"]
	blob = await request.read() # XXX: TODO: ensure maximum blob size!!! (we could get OOMed by big blobs here)
	ref = repo.put_blob(blob)

	# XXX: deliberate and opinionated misinterpretation of atproto spec
	# We will never sniff mimes, and reflect back whatever the client claimed it to be.
	# Thus, the same blob bytes can be referenced with multiple mimes
	ref["mimeType"] = mime  # I can be whatever you want me to be

	return web.json_response(record_to_json({"blob": ref}))


async def sync_get_blob(request: web.Request):
	did = request.query["did"]
	assert(did == repo.did)
	cid = CID.decode(request.query["cid"])

	# XXX: deliberate and opinionated misinterpretation of atproto spec
	# We do not consider any single mime to be directly assocated with a blob
	mime = "application/octet-stream"

	return web.Response(body=repo.get_blob(cid), content_type=mime)

@authenticated
async def firehose_inject(request: web.Request):
	data = await request.read()
	await firehose_broadcast(data)
	return web.Response()

@authenticated
async def bsky_actor_get_preferences(request: web.Request):
	return web.json_response(record_to_json(dag_cbor.decode(repo.get_preferences())))

@authenticated
async def bsky_actor_put_preferences(request: web.Request):
	preference_json = await request.json()
	preference_blob = dag_cbor.encode(json_to_record(preference_json))
	repo.put_preferences(preference_blob)
	return web.Response()

@authenticated
async def bsky_actor_search_actors_typeahead(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.actor.searchActorsTypeahead", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_graph_get_lists(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.graph.getLists", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_graph_get_follows(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.graph.getFollows", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_graph_get_followers(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.graph.getFollowers", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_graph_mute_actor(request: web.Request):
	body = await request.json()
	async with client.post(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.graph.muteActor", params=request.query, json=body, headers=get_appview_auth()) as r:
		return web.Response(body=await r.read(), status=r.status)

@authenticated
async def bsky_actor_get_profile(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.actor.getProfile", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_timeline(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getTimeline", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_author_feed(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getAuthorFeed", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_actor_feeds(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getActorFeeds", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)


@authenticated
async def bsky_notification_list_notifications(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.notification.listNotifications", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_notification_update_seen(request: web.Request):
	body = await request.json()
	async with client.post(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.notification.updateSeen", params=request.query, json=body, headers=get_appview_auth()) as r:
		return web.Response(body=await r.read(), status=r.status)

@authenticated
async def bsky_get_popular_feeds(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.unspecced.getPopularFeedGenerators", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_feed_generator(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getFeedGenerator", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_feed_generators(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getFeedGenerators", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_post_thread(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getPostThread", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_posts(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getPosts", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_likes(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getLikes", params=request.query, headers=get_appview_auth()) as r:
		return web.json_response(await r.json(), status=r.status)

@authenticated
async def bsky_feed_get_feed(request: web.Request):
	async with client.get(f"https://{APPVIEW_SERVER}/xrpc/app.bsky.feed.getFeed", params=request.query, headers=get_appview_auth()) as r:
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
		web.post("/xrpc/app.bsky.graph.muteActor", bsky_graph_mute_actor),

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
		web.get ("/xrpc/com.atproto.sync.getRepo", sync_get_repo),
		web.get ("/xrpc/com.atproto.sync.getCheckout", sync_get_checkout),
		web.get ("/xrpc/com.atproto.sync.getBlob", sync_get_blob),
		web.post("/xrpc/com.atproto.repo.createRecord", repo_create_record),
		web.post("/xrpc/com.atproto.repo.putRecord", repo_create_record), # this should have its own impl at some point!
		web.get ("/xrpc/com.atproto.repo.getRecord", repo_get_record),
		web.post("/xrpc/com.atproto.repo.uploadBlob", repo_upload_blob),
		

		web.post("/xrpc/unspecced.evil.firehoseInject", firehose_inject),
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
	
	LOG_FMT = '%{X-Forwarded-For}i %t (%Tf) "%r" %s %b "%{Referer}i" "%{User-Agent}i"'
	runner = web.AppRunner(app, access_log_format=LOG_FMT)
	await runner.setup()
	site = web.TCPSite(runner, host="localhost", port=31337)
	await site.start()

	while True:
		await asyncio.sleep(3600)  # sleep forever

asyncio.run(main())
