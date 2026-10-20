from pydantic import BaseModel

class LogAnalysis(BaseModel):
    event_count:int
    time_range:dict
    fired_rule_ids:list[str]
    findings:list[dict]
    missing_fields:list[str]
    follow_up_questions:list[str]
def run(events,findings):
    times=[e["timestamp"] for e in events if e.get("timestamp")!="unknown"]
    missing=sorted({key for key in ("username","source_ip","outcome") if sum(bool(e.get(key)) for e in events)<len(events)})
    return LogAnalysis(event_count=len(events),time_range={"first":min(times) if times else None,"last":max(times) if times else None},fired_rule_ids=sorted({f["rule_id"] for f in findings}),findings=findings,missing_fields=missing,follow_up_questions=["Were the affected accounts expected to authenticate from these sources?","Do identity-provider records confirm or deny the observed sequence?"] if findings else ["Are additional host or network logs available for this period?"]).model_dump()
