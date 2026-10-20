from datetime import datetime,timezone
from uuid import uuid4
import time,logging
from ..config import settings
from ..db import SessionLocal
from ..models import AnalysisJob,SecurityEvent,DetectionFinding,Incident,Indicator,AgentExecution,IncidentReport
from ..graph.workflow import workflow

log=logging.getLogger(__name__)
AGENTS=["Log Analysis Agent","Threat Intelligence Agent","Anomaly Analysis Agent","Incident Correlation Agent","Investigation Agent","Report Generator Agent","Quality Controller Agent"]
def utcnow(): return datetime.now(timezone.utc)
def run_job(job_id):
    start=time.monotonic(); db=SessionLocal()
    try:
        job=db.get(AnalysisJob,job_id)
        if not job:return
        job.status="running"; job.stage="loading_events"; job.started_at=utcnow(); db.commit()
        events=db.query(SecurityEvent).filter_by(dataset_id=job.dataset_id).all()
        event_dicts=[{"id":e.id,"timestamp":e.timestamp,"event_type":e.event_type,"username":e.username,"source_ip":e.source_ip,"host":e.host,"outcome":e.outcome,"fields":e.fields} for e in events]
        job.stage="agent_workflow"; db.commit()
        state=workflow.invoke({"job_id":job_id,"events":event_dicts})
        if time.monotonic()-start>settings.max_job_seconds: raise TimeoutError("Analysis exceeded the configured duration limit")
        for f in state.get("findings",[]): db.add(DetectionFinding(id=f["id"],dataset_id=job.dataset_id,rule_id=f["rule_id"],title=f["title"],severity=f["severity"],description=f["description"],event_ids=f["event_ids"]))
        for item in state.get("indicators",[]):
            db.add(Indicator(id=str(uuid4()),dataset_id=job.dataset_id,kind=item["kind"],value=item["value"],validation_status=item["validation_status"],source_event_ids=item["source_event_ids"]))
        reports=state.get("reports",[]); incidents=state.get("incidents",[]); quality=state.get("quality",[])
        for i,(inc,report,q) in enumerate(zip(incidents,reports,quality)):
            inc["summary"]=inc.get("summary") or report["content"]["executive_summary"]
            db.add(Incident(id=inc["id"],dataset_id=job.dataset_id,title=inc["title"],severity=inc["severity"],status=inc["status"],first_seen=inc["first_seen"],last_seen=inc["last_seen"],event_ids=inc["event_ids"],finding_ids=inc["finding_ids"],indicators=inc["indicators"],summary=inc["summary"]))
            db.add(IncidentReport(id=str(uuid4()),incident_id=inc["id"],content=report["content"],markdown=report["markdown"],validation_status="passed" if q["passed"] else "failed"))
        summaries=[("Log Analysis Agent",f"Reviewed {len(events)} normalized events and {len(state.get('findings',[]))} deterministic finding(s)."),("Threat Intelligence Agent",f"Extracted {len(state.get('indicators',[]))} indicators; no automatic external lookups were made."),("Anomaly Analysis Agent",f"Generated {len(state.get('anomalies',{}).get('anomalies',[]))} relative-frequency anomaly signal(s)."),("Incident Correlation Agent",f"Correlated {len(incidents)} candidate incident(s)."),("Investigation Agent",f"Prepared {len(state.get('investigations',[]))} evidence-bound investigation(s)."),("Report Generator Agent",f"Generated {len(reports)} report(s)."),("Quality Controller Agent",f"Validated {sum(bool(x.get('passed')) for x in quality)}/{len(quality)} report(s).")]
        for agent,summary in summaries: db.add(AgentExecution(job_id=job_id,agent=agent,status="completed",summary=summary))
        job.status="completed" if all(x.get("passed") for x in quality) else "completed_with_warnings"; job.stage="complete"; job.ended_at=utcnow(); db.commit()
    except Exception as exc:
        db.rollback(); job=db.get(AnalysisJob,job_id)
        if job: job.status="failed"; job.stage="failed"; job.error=str(exc)[:500]; job.ended_at=utcnow(); db.commit()
        log.exception("Analysis job %s failed",job_id)
    finally: db.close()
