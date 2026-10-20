from collections import defaultdict
from datetime import datetime, timedelta, timezone
from uuid import uuid4

def _dt(value):
    try: return datetime.fromisoformat(value.replace("Z","+00:00"))
    except (ValueError,AttributeError): return None
def failed(event):
    val=(event.get("outcome") or "").lower(); typ=(event.get("event_type") or "").lower()
    return val in {"failure","failed","fail","denied","invalid","error"} or "failed" in typ or "failure" in typ
def successful(event): return (event.get("outcome") or "").lower() in {"success","succeeded","ok","allowed"} or "success" in (event.get("event_type") or "").lower()
def detect(events):
    ordered=sorted(events,key=lambda e:_dt(e["timestamp"]) or datetime.min.replace(tzinfo=timezone.utc)); findings=[]
    by_source=defaultdict(list); by_pair=defaultdict(list)
    for e in ordered:
        if e.get("source_ip"):
            by_source[e["source_ip"]].append(e)
        if e.get("source_ip") and e.get("username"): by_pair[(e["source_ip"],e["username"])].append(e)
    def add(rule,title,severity,desc,items):
        ids=list(dict.fromkeys(x["id"] for x in items))
        if ids: findings.append({"id":str(uuid4()),"rule_id":rule,"title":title,"severity":severity,"description":desc,"event_ids":ids})
    for (ip,user),items in by_pair.items():
        fails=[e for e in items if failed(e)]
        for i in range(len(fails)):
            start=_dt(fails[i]["timestamp"])
            if start is None: continue
            window=[e for e in fails[i:] if (t:=_dt(e["timestamp"])) and t-start<=timedelta(minutes=10)]
            if len(window)>=5:
                add("AUTH-001","Repeated failed authentication","high",f"{len(window)} failed authentication events for one account from {ip} within 10 minutes.",window); break
        for i,e in enumerate(items):
            if successful(e):
                t=_dt(e["timestamp"])
                prior=[x for x in fails if _dt(x["timestamp"]) and t and timedelta(0)<=t-_dt(x["timestamp"])<=timedelta(minutes=15)]
                if len(prior)>=3: add("AUTH-003","Authentication success after repeated failures","high",f"A successful authentication followed {len(prior)} failures for the same account and source within 15 minutes.",prior+[e]); break
    for ip,items in by_source.items():
        relevant=[e for e in items if failed(e)]
        relevant.sort(key=lambda e:_dt(e["timestamp"]) or datetime.min.replace(tzinfo=timezone.utc))
        for i,start_event in enumerate(relevant):
            start=_dt(start_event["timestamp"])
            if start is None:continue
            window=[e for e in relevant[i:] if (t:=_dt(e["timestamp"])) and t-start<=timedelta(minutes=15)]
            users={e.get("username") for e in window if e.get("username")}
            if len(users)>=3:
                add("AUTH-002","One source targeted multiple accounts","high",f"{ip} generated failed authentication events for {len(users)} distinct accounts within 15 minutes; investigate for password spraying.",window);break
    for e in ordered:
        if (e.get("username") or "").lower() in {"admin","administrator","root","domain admin","system"} and successful(e):
            add("AUTH-004","Privileged account authentication","medium","Successful activity used a privileged account name; verify expected access and change context.",[e])
    return findings
