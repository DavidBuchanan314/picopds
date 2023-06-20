from multiformats import CID

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

def json_to_record(data):
	if type(data) is list:
		return [json_to_record(r) for r in data]
	if type(data) is dict:
		if len(data) == 1 and "$link" in data:
			return CID.decode(data["$link"])
		return {k: json_to_record(v) for k, v in data.items()}
	return data
