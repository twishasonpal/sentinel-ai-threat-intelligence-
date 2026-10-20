import ipaddress,re
from pydantic import BaseModel

class IndicatorFinding(BaseModel): kind:str; value:str; validation_status:str; source_event_ids:list[str]
def extract(events):
    found={}
    for e in events:
        texts=[]
        if e.get("source_ip"):texts.append(e["source_ip"])
        def visit(value):
            if isinstance(value,str):texts.append(value)
            elif isinstance(value,dict):
                for v in value.values():visit(v)
            elif isinstance(value,list):
                for v in value:visit(v)
        visit(e.get("fields",{}))
        candidates=[]
        for text in texts:
            candidates.append(("url",re.findall(r"https?://[^\s\"'<>]+",text,re.I)))
            candidates.append(("hash",re.findall(r"(?i)\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b",text)))
            candidates.append(("ip",re.findall(r"(?<![a-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![a-z0-9])|(?<![a-z0-9:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![a-z0-9:])",text,re.I)))
            candidates.append(("domain",re.findall(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",text)))
        for kind,values in candidates:
            for value in values:
                value=value.rstrip(".,);]")
                status="valid"
                if kind=="ip":
                    try:
                        ip=ipaddress.ip_address(value); value=str(ip); status="private_or_reserved" if not ip.is_global else "valid_public"
                    except ValueError:status="malformed"
                elif kind=="url":status="valid_syntax_only"
                key=(kind,value.lower() if kind in {"domain","hash"} else value)
                record=found.setdefault(key,{"kind":kind,"value":key[1],"validation_status":status,"source_event_ids":[]})
                if e["id"] not in record["source_event_ids"]:record["source_event_ids"].append(e["id"])
    return [IndicatorFinding(**v).model_dump() for v in found.values()]
