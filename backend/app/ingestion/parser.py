import csv, io, json, re
import ipaddress
from datetime import datetime, timezone
from uuid import uuid4
from pydantic import ValidationError
from ..schemas import NormalizedEvent

SECRET=re.compile(r"password|passwd|token|secret|authorization|cookie|credential|api.?key",re.I)
ASSIGNMENT=re.compile(r"(?i)(password|passwd|token|secret|authorization|api[_-]?key)\s*[:=]\s*[^\s,;]+")
def _clean(value):
    if isinstance(value,dict): return {str(k):("[REDACTED]" if SECRET.search(str(k)) else _clean(v)) for k,v in value.items() if not SECRET.search(str(k))}
    if isinstance(value,list): return [_clean(x) for x in value[:500]]
    if isinstance(value,str): return ASSIGNMENT.sub(r"\1=[REDACTED]",value.replace("Bearer ","Bearer [REDACTED]"))[:2000]
    if isinstance(value,(int,float,bool)) or value is None: return value
    return str(value)[:2000]
def _pick(row,*keys):
    low={str(k).lower():v for k,v in row.items()}
    return next((low[k] for k in keys if low.get(k) not in (None,"")),None)
def normalize(row,index):
    if not isinstance(row,dict): raise ValueError(f"row {index}: expected an object")
    ts=_pick(row,"timestamp","time","@timestamp","date","event_time")
    if not ts: ts="unknown"
    else:
        try:
            parsed=datetime.fromisoformat(str(ts).replace("Z","+00:00"))
            if parsed.tzinfo is None: parsed=parsed.replace(tzinfo=timezone.utc)
            ts=parsed.astimezone(timezone.utc).isoformat()
        except ValueError: raise ValueError(f"row {index}: invalid timestamp")
    source_ip=str(_pick(row,"source_ip","src_ip","ip","client_ip","remote_addr") or "")[:64] or None
    if source_ip:
        try:source_ip=str(ipaddress.ip_address(source_ip))
        except ValueError:source_ip=None
    return NormalizedEvent(event_key=str(_pick(row,"event_id","id","eventid") or uuid4()),timestamp=ts,event_type=str(_pick(row,"event_type","eventtype","action","type") or "unknown").lower()[:100],username=str(_pick(row,"username","user","account","principal") or "")[:255] or None,source_ip=source_ip,host=str(_pick(row,"host","hostname","device") or "")[:255] or None,outcome=str(_pick(row,"outcome","status","result") or "")[:64].lower() or None,fields=_clean(row)).model_dump()
def parse_bytes(data:bytes,filename:str,max_events:int):
    suffix=filename.lower().rsplit(".",1)[-1]
    try:
        text=data.decode("utf-8-sig")
        if suffix=="csv": rows=list(csv.DictReader(io.StringIO(text)))
        elif suffix=="jsonl": rows=[json.loads(line) for line in text.splitlines() if line.strip()]
        elif suffix=="json":
            parsed=json.loads(text); rows=parsed if isinstance(parsed,list) else parsed.get("events") if isinstance(parsed,dict) else None
            if not isinstance(rows,list): raise ValueError("JSON must be an array or an object with an events array")
        else: raise ValueError("Only .json, .jsonl, and .csv files are accepted")
    except (UnicodeDecodeError,json.JSONDecodeError,csv.Error) as exc: raise ValueError("Input file is malformed or is not UTF-8") from exc
    if not rows: raise ValueError("The dataset contains no events")
    if len(rows)>max_events: raise ValueError(f"Dataset exceeds the {max_events} event limit")
    events=[]; errors=[]; seen=set()
    for i,row in enumerate(rows,1):
        try:
            event=normalize(row,i)
            if event["event_key"] in seen: raise ValueError("duplicate event ID")
            seen.add(event["event_key"]); events.append(event)
        except (ValueError,ValidationError) as exc: errors.append(str(exc))
    if not events: raise ValueError("No valid events were found")
    return events,errors
