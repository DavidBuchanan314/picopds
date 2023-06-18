from multiformats import CID

def record_to_json(record):
	if type(record) is list:
		return [record_to_json(r) for r in record]
	if type(record) is dict:
		return {k: record_to_json(v) for k, v in record.items()}
	if type(record) is CID:
		return {"$link": record.encode("base32")}
	return record
