import dag_cbor
from multiformats import CID
from typing import Iterable, Tuple, List

# leb128
def varint_encode(n: int) -> bytes:
	result = []
	while n:
		n, x = divmod(n, 128)
		result.append(x | ((n!=0)<<7))
	return bytes(result)

# note: this function expects block CIDS and values to be pre-serialised, but not roots!
def serialise(roots: List[CID], blocks: Iterable[Tuple[bytes, bytes]]) -> bytes:
	result = b""
	header = dag_cbor.encode({
		"version": 1,
		"roots": roots
	})
	result += varint_encode(len(header)) + header
	for block_cid, block_data in blocks:
		result += varint_encode(len(block_cid) + len(block_data)) + block_cid + block_data
	return result
