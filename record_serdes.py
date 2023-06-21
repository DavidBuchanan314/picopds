from multiformats import CID

"""
concepts:

"record" object is python object representation of a dag_cbor blob.
CIDs are represented with the CID class.

a "json" object is also a python object representation, but CIDs are referenced as {"$link": ...}
(and non-json-representable types, like bytes, are forbidden)

There are probably some fun round-trip breakage bugs relating to $link
"""


def record_to_json(record):
	if type(record) is list:
		return [record_to_json(r) for r in record]
	if type(record) is dict:
		# XXX: detect/prevent dicts containing only $link key?
		return {k: record_to_json(v) for k, v in record.items()}
	if type(record) is CID:
		return {"$link": record.encode("base32")}
	if type(record) is bytes:
		raise TypeError("can't represent bytes as JSON")
	return record

# used to find blob references in a lexicon-oblivious way
def enumerate_record_cids(record):
	if type(record) is list:
		for r in record:
			yield from enumerate_record_cids(r)
	if type(record) is dict:
		for r in record.values():
			yield from enumerate_record_cids(r)
	if type(record) is CID:
		yield record

def json_to_record(data):
	if type(data) is list:
		return [json_to_record(r) for r in data]
	if type(data) is dict:
		if len(data) == 1 and "$link" in data:
			return CID.decode(data["$link"])
		return {k: json_to_record(v) for k, v in data.items()}
	return data
