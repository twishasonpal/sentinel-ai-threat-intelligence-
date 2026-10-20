from datetime import datetime
from uuid import uuid4

def correlate(events,findings):
    by_id={e["id"]:e for e in events}; groups=[]
    def related_in_time(left_ids,right_ids):
        for left in left_ids:
            try:lt=datetime.fromisoformat(by_id[left]["timestamp"].replace("Z","+00:00"))
            except (ValueError,KeyError):continue
            for right in right_ids:
                try:rt=datetime.fromisoformat(by_id[right]["timestamp"].replace("Z","+00:00"))
                except (ValueError,KeyError):continue
                if abs((lt-rt).total_seconds())<=1800:return True
        return False
    for finding in findings:
        ids=set(finding["event_ids"]); keys={((by_id[x].get("source_ip")),(by_id[x].get("username"))) for x in ids if x in by_id}
        merged=[]
        for group in groups:
            other_keys=group["keys"]
            same_indicator=any((a and a==c) or (b and b==d) for a,b in keys for c,d in other_keys)
            if ids & group["ids"] or same_indicator and related_in_time(ids,group["ids"]):
                ids|=group["ids"]; keys|=other_keys; merged.append(group)
        groups=[g for g in groups if g not in merged]; groups.append({"ids":ids,"keys":keys,"findings":[finding] + [f for g in merged for f in g["findings"]]})
    incidents=[]
    for group in groups:
        related=[by_id[x] for x in group["ids"] if x in by_id]; related.sort(key=lambda e:e["timestamp"])
        if not related: continue
        findings_for=group["findings"]
        severity=max((f["severity"] for f in findings_for),key=lambda s:{"critical":4,"high":3,"medium":2,"low":1,"info":0}.get(s,0))
        incidents.append({"id":str(uuid4()),"title":findings_for[0]["title"],"severity":severity,"status":"open","first_seen":related[0]["timestamp"],"last_seen":related[-1]["timestamp"],"event_ids":[e["id"] for e in related],"finding_ids":list(dict.fromkeys(f["id"] for f in findings_for)),"indicators":list(dict.fromkeys(e["source_ip"] for e in related if e.get("source_ip"))),"timeline":[{"event_id":e["id"],"timestamp":e["timestamp"],"event_type":e["event_type"],"username":e.get("username"),"source_ip":e.get("source_ip"),"outcome":e.get("outcome")} for e in related]})
    return incidents
