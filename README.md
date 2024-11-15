> [!NOTE]  
> My current focus is on [millipds](https://github.com/DavidBuchanan314/millipds), a more "production grade" rewrite of picopds. picopds is no longer maintained (not that it ever really was in the first place, lol).

# picopds
A minimum viable atproto PDS for protocol experimentation purposes

It's designed to be a single-user instance (i.e. it only hosts a single repo). This is a hardcoded constraint right now but I might make multiple repos technically possible at some point.

## NOTE: This is experimental software, it may explode and eat all your data, etc. etc.

### What works:

- Creating a new DID and publishing it.
- Creating new records (making posts, liking, replying, following, etc.)
- Deleting records (post deletion, unlikes, unfollows, etc.)
- Attaching blobs (e.g. images)
- Editing records (e.g. editing bio).
- Federated firehose.
- AppView proxying for most bsky endpoints (still missing some)

### What doesn't work yet:

- Updating records works but is subtly incorrect (e.g. it will leak blob references)
- swapCommit/swapRecord options for repo ops (they're silently ignored).
- Firehose cursoring.
- Handle firehose "too big" conditions.
- No Lexicon validation (the client is assumed to be well-behaved!)
- A lot of error/unhappy-path handling (and sometimes we signal errors in non-standard ways).
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

4. Create an `_atproto` TXT DNS record that points your handle domain name to your DID (or alternatively use the HTTP method) (more info [here](https://blueskyweb.xyz/blog/4-28-2023-domain-handle-tutorial)).

5. Run `pds.py`, and make the web server publicly accessible somewhere (I'm using an nginx reverse proxy). You might want to create a systemd unit, or docker container, or something like that (I wouldn't know, I suck at devops/sysadmin).

6. Run `request_crawl.py` to inform the PDS that we exist. (Maybe I'll make this automatic at some point in the future).

7. Log in with a client (the official https://bsky.app works) and make a post, and the BGS should see it!
