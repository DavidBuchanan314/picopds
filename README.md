# picopds
A minimum viable atproto PDS for protocol experimentation purposes

It's designed to be a single-user instance (i.e. it only hosts a single repo). This is a hardcoded constraint right now but I might make multiple repos technically possible at some point.

### What works:

- Creating a new DID and publishing it.
- Creating new records (making posts, liking, replying).
- Attaching blobs (e.g. images)
- Editing records (e.g. editing bio).
- Federated firehose.
- AppView proxying for most endpoints (still missing some)

### What doesn't work yet:

- Deleting records (no post deletion, no unlikes, no unfollows!)
- Firehose cursoring.
- No Lexicon validation (the client is assumed to be well-behaved!)
- A lot of error/unhappy-path handling.
- JWT refresh tokens
- Various security considerations (e.g. password hashing)
- Many many many other things...

### TODO:

 - Fix aforementioned non-working things
 - Figure out how to garbage-collect MST blocks
 - Don't hold full MST state in memory, load blocks from DB on-demand
 - Put blobs larger than some threshold in the filesystem, not in sqlite
 - Tests
 - Docs

### Planned Extended Features:

 - Design and implement a protocol for client-signed commits (so the server can avoid holding signing keys, and enabling the use of user-local HSMs)

 - A read-only web interface for external sharing of posts.

### Usage:

1. Copy `config.py.example` to `config.py`, and edit it.

2. Run `python3 create_identity.py`

3. Update `config.py` with the new DID value you just generated

4. Run `pds.py`, and make the web server publicly accessible somewhere (I'm using an nginx reverse proxy)

5. Run `request_crawl.py` to inform the PDS that we exist.

6. Log in with a client (the official https://bsky.app works) and make a post, and the BGS should see it!
