import hashlib
import dag_cbor
from multiformats import multihash, CID
from typing import Self, List, Tuple, Optional
from more_itertools import ilen
from itertools import takewhile
from functools import cached_property
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
import operator
import sqlite3
import random
import time
import datetime

from mst import MSTNode
from signing import raw_sign
import carfile

B32_CHARSET = "234567abcdefghijklmnopqrstuvwxyz"

def tid_now():
	nanos = int(time.time()*1000000)
	clkid = random.randrange(1<<10)
	tid_int = (nanos << 10) | clkid
	return "".join(B32_CHARSET[(tid_int >> (60-(i * 5))) & 31] for i in range(13))

def hash_to_cid(data: bytes) -> CID:
	digest = multihash.digest(data, "sha2-256")
	return CID("base58btc", 1, "dag-cbor", digest)

class ATNode(MSTNode):
	@staticmethod
	def key_height(key: str) -> int:
		digest = int.from_bytes(hashlib.sha256(key.encode()).digest(), "big")
		leading_zeroes = 256 - digest.bit_length()
		return leading_zeroes // 2

	def get_key_path(self, key: str) -> List[str]:
		key_height = self.key_height(key)
		tree_height = self.height()
		if key_height > tree_height:
			return None
		if key_height < tree_height:
			subtree = self.subtrees[self._gte_index(key)]
			if subtree is None:
				return None
			return [self.cid()] + subtree.get_key_path(key)
		i = self._gte_index(key)
		if i == len(self.keys):
			return None
		if self.keys[i] != key:
			return None
		return [self.cid()]
	
	def get_all_blocks(self):
		yield self.cid()
		for subtree in self.subtrees:
			if subtree is None:
				continue
			yield from subtree.get_all_blocks()
		yield from self.vals

	# since we're immutable, this can be cached
	@cached_property
	def cid(self: Self) -> CID:
		digest = multihash.digest(self.serialised, "sha2-256")
		cid = CID("base58btc", 1, "dag-cbor", digest)
		return cid

	# likewise
	@cached_property
	def serialised(self: Self) -> bytes:
		e = []
		prev_key = b""
		for t, k, v in zip(self.subtrees[1:], self.keys, self.vals):
			key_bytes = k.encode()
			shared_prefix_len = ilen(takewhile(bool, map(operator.eq, prev_key, key_bytes))) # I love functional programming
			e.append({
				"k": key_bytes[shared_prefix_len:],
				"p": shared_prefix_len,
				"t": None if t is None else t.cid,
				"v": v,
			})
			prev_key = key_bytes
		return dag_cbor.encode({
			"e": e,
			"l": None if self.subtrees[0] is None else self.subtrees[0].cid
		})

	def __hash__(self) -> int:
		return hash(self.cid)
	
	def __eq__(self, __value: object) -> bool:
		if type(__value) is not self.__class__:
			return False
		return self.cid == __value.cid

class Repo:
	def __init__(self, did, db: str, signing_key: EllipticCurvePrivateKey) -> None:
		self.did = did
		self.con = sqlite3.connect(db)
		self.signing_key = signing_key
		self.cur = self.con.cursor()
		self.cur.execute("""CREATE TABLE IF NOT EXISTS records (
			record_key TEXT PRIMARY KEY NOT NULL,
			record_cid BLOB NOT NULL
		)""")
		self.cur.execute("""CREATE TABLE IF NOT EXISTS blocks (
			block_cid BLOB PRIMARY KEY NOT NULL,
			block_value BLOB NOT NULL
		)""")

		# TODO: persist firehose
		#self.cur.execute("""CREATE TABLE IF NOT EXISTS firehose (
		#	firehose_seq INTEGER PRIMARY KEY NOT NULL,
		#	firehose_msg BLOB NOT NULL
		#)""")

		# is autoincrement the right choice here?
		self.cur.execute("""CREATE TABLE IF NOT EXISTS commits (
			commit_seq INTEGER PRIMARY KEY NOT NULL,
			commit_cid BLOB NOT NULL
		)""")

		self.tree = ATNode.empty_root()

		# make an empty first commit, if it doesn't already exist
		if self.cur.execute("SELECT * FROM commits WHERE commit_seq=0").fetchone() is None:
			commit = {
				"version": 2,
				"data": self.tree.cid,
				"prev": None,
				"did": self.did
			}
			commit["sig"] = raw_sign(self.signing_key, dag_cbor.encode(commit))
			commit_blob = dag_cbor.encode(commit)
			commit_cid = hash_to_cid(commit_blob)
			self.cur.executemany("""INSERT OR IGNORE INTO blocks (
				block_cid, block_value
			) VALUES (?, ?)""", [(bytes(self.tree.cid), self.tree.serialised), (bytes(commit_cid), commit_blob)])
			self.cur.execute("""INSERT INTO commits (
				commit_seq, commit_cid
			) VALUES (?, ?)""", (0, bytes(commit_cid)))
			self.con.commit()

		# this is kinda expensive but it's the price we pay for maintaining an
		# in-memory MST
		for record_key, value_cid in self.cur.execute("SELECT record_key, record_cid FROM records"):
			self.tree = self.tree.put(record_key, CID.decode(value_cid), set())
		
		# TODO: check that root cid matches that of the last commit in sqlite
	
	def create_record(self, collection, value, rkey=None) -> Tuple[str, CID]:
		if rkey is None:
			rkey = tid_now()
		
		record_key = f"{collection}/{rkey}"

		value_bytes = dag_cbor.encode(value)
		value_cid = hash_to_cid(value_bytes)
		db_block_inserts = [(bytes(value_cid), value_bytes)]

		new_blocks = set()
		self.tree = self.tree.put(record_key, value_cid, new_blocks)
		for block in new_blocks:
			db_block_inserts.append((bytes(block.cid), block.serialised))

		prev_commit_seq, prev_commit = self.cur.execute("SELECT commit_seq, commit_cid FROM commits ORDER BY commit_seq DESC LIMIT 1").fetchone()
		prev_commit_cid = CID.decode(prev_commit)

		commit = {
			"version": 2,
			"data": self.tree.cid,
			"prev": prev_commit_cid,
			"did": self.did
		}
		commit["sig"] = raw_sign(self.signing_key, dag_cbor.encode(commit))
		commit_blob = dag_cbor.encode(commit)
		commit_cid = hash_to_cid(commit_blob)
		db_block_inserts.append((bytes(commit_cid), commit_blob))

		#print(db_block_inserts)
		#print(self.tree)
		firehose_blob = dag_cbor.encode({
			"t": "#commit",
			"op": 1
		}) + dag_cbor.encode({
			"ops": [{
				"cid": value_cid,
				"path": record_key,
				"action": "create"
			}],
			"seq": int(time.time()*1000000), # TODO: don't use timestamp (requires persisting firehose history)
			"prev": prev_commit_cid, # TODO: is this correct?
			"repo": self.did,
			"time": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
			"blobs": [],
			"blocks": carfile.serialise([commit_cid], db_block_inserts),
			"commit": commit_cid,
			"rebase": False,
			"tooBig": False # TODO: actually check lol
		})

		self.con.executemany("""INSERT OR IGNORE INTO blocks (
			block_cid, block_value
		) VALUES (?, ?)""", db_block_inserts)

		# technically we should only REPLACE if this is a putrecord
		self.con.execute("INSERT OR REPLACE INTO records (record_key, record_cid) VALUES (?, ?)", (record_key, bytes(value_cid)))

		self.con.execute("INSERT INTO commits (commit_seq, commit_cid) VALUES (?, ?)", (prev_commit_seq + 1, bytes(commit_cid)))
		self.con.commit()

		return f"at://{self.did}/{record_key}", value_cid, firehose_blob

	def get_checkout(self, commit: Optional[CID]=None):
		if commit is None:
			_, prev_commit = self.cur.execute("SELECT commit_seq, commit_cid FROM commits ORDER BY commit_seq DESC LIMIT 1").fetchone()
			commit = CID.decode(prev_commit)
		
		# HACK: we're going to return every block in our DB regardless of if its needed
		blocks = self.cur.execute("SELECT block_cid, block_value FROM blocks")
		return carfile.serialise([commit], blocks)


if __name__ == "__main__":
	repo = Repo("repo.db")
	print(repo.tree)
	#repo.create_record("app.bsky.feed.post", {"foo": "bar"}, "self")
