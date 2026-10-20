from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
from pathlib import Path
from uuid import uuid4
import logging
from flask import Flask,jsonify,request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydantic import ValidationError
from sqlalchemy import text
from .config import settings
from .db import Base,engine,SessionLocal
from .models import Dataset,SecurityEvent,DetectionFinding,Incident,AnalysisJob,Indicator,ThreatIntelResult,AgentExecution,IncidentReport,HumanReview
from .ingestion.parser import parse_bytes
from .schemas import ReviewRequest,LookupRequest
from .services.jobs import run_job
from .integrations.virustotal import normalize_indicator,lookup_virustotal,IndicatorError

logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger=logging.getLogger("sentinel")
workers=ThreadPoolExecutor(max_workers=2,thread_name_prefix="sentinel-job")
def _json_error(message,status): return jsonify({"error":message}),status
def create_app(test_config=None):
    app=Flask(__name__); app.config.update(test_config or {}); app.config["MAX_CONTENT_LENGTH"]=settings.max_upload_bytes
    CORS(app,origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()])
    Limiter(get_remote_address,app=app,default_limits=["120 per minute"])
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        for job in db.query(AnalysisJob).filter(AnalysisJob.status.in_(["queued","running"])).all():
            job.status="interrupted"; job.stage="interrupted"; job.error="Worker process restarted before the job completed"
        db.commit()

    def create_dataset(filename,data):
        if len(data)>settings.max_upload_bytes: return None,("Upload exceeds configured size limit",413)
        try: events,errors=parse_bytes(data,filename,settings.max_events)
        except ValueError as exc: return None,(str(exc),400)
        suffix=filename.rsplit(".",1)[-1].lower()
        with SessionLocal() as db:
            dataset=Dataset(id=str(uuid4()),name=Path(filename).name[:255],data_type=suffix,event_count=len(events),status="ready",error="; ".join(errors[:10]) or None); db.add(dataset)
            for item in events: db.add(SecurityEvent(id=str(uuid4()),dataset_id=dataset.id,event_key=item["event_key"],timestamp=item["timestamp"],event_type=item["event_type"],username=item["username"],source_ip=item["source_ip"],host=item["host"],outcome=item["outcome"],fields=item["fields"]))
            db.commit(); return {"id":dataset.id,"name":dataset.name,"data_type":dataset.data_type,"event_count":dataset.event_count,"status":dataset.status,"warnings":errors[:10]},None

    @app.get("/api/v1/health")
    def health():
        try:
            with engine.connect() as conn: conn.execute(text("SELECT 1"))
            dbstatus="ok"
        except Exception: dbstatus="unavailable"
        return jsonify({"status":"ok" if dbstatus=="ok" else "degraded","database":dbstatus,"ai_configured":bool(settings.enable_ai and settings.gemini_api_key),"threat_intel_configured":bool(settings.intel_provider and settings.intel_api_key)})
    @app.get("/api/v1/overview")
    def overview():
        with SessionLocal() as db:
            return jsonify({"datasets":db.query(Dataset).count(),"events":db.query(SecurityEvent).count(),"findings":db.query(DetectionFinding).count(),"open_incidents":db.query(Incident).filter_by(status="open").count(),"jobs":[{"id":j.id,"dataset_id":j.dataset_id,"status":j.status,"stage":j.stage,"created_at":j.created_at.isoformat()} for j in db.query(AnalysisJob).order_by(AnalysisJob.created_at.desc()).limit(8)]})
    @app.post("/api/v1/datasets")
    def upload_dataset():
        f=request.files.get("file")
        if not f or not f.filename: return _json_error("Upload a JSON, JSONL, or CSV file in the 'file' field",400)
        result,error=create_dataset(Path(f.filename).name,f.read(settings.max_upload_bytes+1))
        if error:return _json_error(*error)
        return jsonify(result),201
    @app.post("/api/v1/datasets/sample")
    def sample_dataset():
        path=Path(__file__).resolve().parents[2]/"sample_data"/"auth_events.jsonl"
        try: data=path.read_bytes()
        except OSError:return _json_error("Synthetic sample data is unavailable",500)
        result,error=create_dataset("synthetic-auth-events.jsonl",data)
        if error:return _json_error(*error)
        result["label"]="synthetic sample data"; return jsonify(result),201
    @app.get("/api/v1/datasets")
    def list_datasets():
        page=max(1,request.args.get("page",1,type=int)); limit=min(100,max(1,request.args.get("limit",25,type=int)))
        with SessionLocal() as db:
            rows=db.query(Dataset).order_by(Dataset.created_at.desc()).offset((page-1)*limit).limit(limit).all()
            return jsonify({"items":[{"id":d.id,"name":d.name,"data_type":d.data_type,"created_at":d.created_at.isoformat(),"event_count":d.event_count,"status":d.status,"error":d.error} for d in rows],"page":page,"limit":limit})
    @app.get("/api/v1/datasets/<dataset_id>")
    def dataset_detail(dataset_id):
        with SessionLocal() as db:
            d=db.get(Dataset,dataset_id)
            if not d:return _json_error("Dataset not found",404)
            return jsonify({"id":d.id,"name":d.name,"data_type":d.data_type,"created_at":d.created_at.isoformat(),"event_count":d.event_count,"status":d.status,"error":d.error})
    @app.get("/api/v1/datasets/<dataset_id>/events")
    def dataset_events(dataset_id):
        page=max(1,request.args.get("page",1,type=int)); limit=min(200,max(1,request.args.get("limit",50,type=int)))
        with SessionLocal() as db:
            if not db.get(Dataset,dataset_id):return _json_error("Dataset not found",404)
            q=db.query(SecurityEvent).filter_by(dataset_id=dataset_id)
            severity=request.args.get("event_type")
            if severity:q=q.filter(SecurityEvent.event_type==severity)
            rows=q.order_by(SecurityEvent.timestamp).offset((page-1)*limit).limit(limit).all()
            return jsonify({"items":[{"id":e.id,"event_key":e.event_key,"timestamp":e.timestamp,"event_type":e.event_type,"username":e.username,"source_ip":e.source_ip,"host":e.host,"outcome":e.outcome,"fields":e.fields} for e in rows],"page":page,"limit":limit})
    @app.delete("/api/v1/datasets/<dataset_id>")
    def delete_dataset(dataset_id):
        with SessionLocal() as db:
            d=db.get(Dataset,dataset_id)
            if not d:return _json_error("Dataset not found",404)
            incident_ids=[x[0] for x in db.query(Incident.id).filter_by(dataset_id=dataset_id).all()]
            job_ids=[x[0] for x in db.query(AnalysisJob.id).filter_by(dataset_id=dataset_id).all()]
            indicator_ids=[x[0] for x in db.query(Indicator.id).filter_by(dataset_id=dataset_id).all()]
            if incident_ids:
                db.query(HumanReview).filter(HumanReview.incident_id.in_(incident_ids)).delete(synchronize_session=False)
                db.query(IncidentReport).filter(IncidentReport.incident_id.in_(incident_ids)).delete(synchronize_session=False)
            if job_ids:db.query(AgentExecution).filter(AgentExecution.job_id.in_(job_ids)).delete(synchronize_session=False)
            if indicator_ids:db.query(ThreatIntelResult).filter(ThreatIntelResult.indicator_id.in_(indicator_ids)).delete(synchronize_session=False)
            for model in (SecurityEvent,DetectionFinding,Incident,AnalysisJob,Indicator):db.query(model).filter_by(dataset_id=dataset_id).delete(synchronize_session=False)
            db.delete(d); db.commit(); return "",204
    @app.post("/api/v1/datasets/<dataset_id>/analyze")
    def analyze_dataset(dataset_id):
        with SessionLocal() as db:
            d=db.get(Dataset,dataset_id)
            if not d:return _json_error("Dataset not found",404)
            job=AnalysisJob(id=str(uuid4()),dataset_id=dataset_id,status="queued",stage="queued"); db.add(job); db.commit(); job_id=job.id
        workers.submit(run_job,job_id)
        return jsonify({"id":job_id,"dataset_id":dataset_id,"status":"queued","stage":"queued"}),202
    @app.get("/api/v1/jobs/<job_id>")
    def get_job(job_id):
        with SessionLocal() as db:
            j=db.get(AnalysisJob,job_id)
            if not j:return _json_error("Job not found",404)
            return jsonify({"id":j.id,"dataset_id":j.dataset_id,"status":j.status,"stage":j.stage,"error":j.error,"created_at":j.created_at.isoformat(),"started_at":j.started_at.isoformat() if j.started_at else None,"ended_at":j.ended_at.isoformat() if j.ended_at else None})
    @app.get("/api/v1/jobs/<job_id>/trace")
    def job_trace(job_id):
        with SessionLocal() as db:
            if not db.get(AnalysisJob,job_id):return _json_error("Job not found",404)
            rows=db.query(AgentExecution).filter_by(job_id=job_id).order_by(AgentExecution.id).all()
            return jsonify([{"agent":x.agent,"status":x.status,"summary":x.summary,"at":x.created_at.isoformat()} for x in rows])
    @app.get("/api/v1/datasets/<dataset_id>/findings")
    def dataset_findings(dataset_id):
        with SessionLocal() as db:
            if not db.get(Dataset,dataset_id):return _json_error("Dataset not found",404)
            q=db.query(DetectionFinding).filter_by(dataset_id=dataset_id)
            if request.args.get("severity"):q=q.filter_by(severity=request.args["severity"])
            return jsonify([{"id":f.id,"rule_id":f.rule_id,"title":f.title,"severity":f.severity,"description":f.description,"event_ids":f.event_ids,"detected_at":f.detected_at.isoformat()} for f in q.order_by(DetectionFinding.detected_at.desc()).all()])
    @app.get("/api/v1/incidents")
    def incidents():
        with SessionLocal() as db:
            q=db.query(Incident)
            for key in ("severity","status","dataset_id"):
                if request.args.get(key):q=q.filter(getattr(Incident,key)==request.args[key])
            return jsonify([{"id":i.id,"dataset_id":i.dataset_id,"title":i.title,"severity":i.severity,"status":i.status,"first_seen":i.first_seen,"last_seen":i.last_seen,"event_ids":i.event_ids,"finding_ids":i.finding_ids,"indicators":i.indicators,"summary":i.summary} for i in q.order_by(Incident.first_seen.desc()).limit(200).all()])
    @app.get("/api/v1/incidents/<incident_id>")
    def incident_detail(incident_id):
        with SessionLocal() as db:
            i=db.get(Incident,incident_id)
            if not i:return _json_error("Incident not found",404)
            events=db.query(SecurityEvent).filter(SecurityEvent.id.in_(i.event_ids)).all() if i.event_ids else []
            findings=db.query(DetectionFinding).filter(DetectionFinding.id.in_(i.finding_ids)).all() if i.finding_ids else []
            reviews=db.query(HumanReview).filter_by(incident_id=i.id).order_by(HumanReview.reviewed_at.desc()).all()
            job=db.query(AnalysisJob).filter_by(dataset_id=i.dataset_id).order_by(AnalysisJob.created_at.desc()).first()
            trace=db.query(AgentExecution).filter_by(job_id=job.id).all() if job else []
            report=db.query(IncidentReport).filter_by(incident_id=i.id).order_by(IncidentReport.created_at.desc()).first()
            return jsonify({"id":i.id,"dataset_id":i.dataset_id,"title":i.title,"severity":i.severity,"status":i.status,"first_seen":i.first_seen,"last_seen":i.last_seen,"summary":i.summary,"indicators":i.indicators,"events":[{"id":e.id,"timestamp":e.timestamp,"event_type":e.event_type,"username":e.username,"source_ip":e.source_ip,"host":e.host,"outcome":e.outcome,"fields":e.fields} for e in sorted(events,key=lambda x:x.timestamp)],"findings":[{"id":f.id,"rule_id":f.rule_id,"title":f.title,"severity":f.severity,"description":f.description,"event_ids":f.event_ids} for f in findings],"report":report.content if report else None,"markdown":report.markdown if report else None,"trace":[{"agent":x.agent,"status":x.status,"summary":x.summary} for x in trace],"reviews":[{"decision":x.decision,"note":x.note,"reviewer":x.reviewer,"reviewed_at":x.reviewed_at.isoformat()} for x in reviews]})
    @app.get("/api/v1/incidents/<incident_id>/report")
    def incident_report(incident_id):
        with SessionLocal() as db:
            if not db.get(Incident,incident_id):return _json_error("Incident not found",404)
            report=db.query(IncidentReport).filter_by(incident_id=incident_id).order_by(IncidentReport.created_at.desc()).first()
            if not report:return _json_error("Report not found",404)
            return jsonify({"content":report.content,"markdown":report.markdown,"validation_status":report.validation_status})
    @app.post("/api/v1/incidents/<incident_id>/review")
    def review_incident(incident_id):
        try: body=ReviewRequest.model_validate(request.get_json(force=True))
        except (ValidationError,ValueError):return _json_error("Invalid review payload",400)
        if body.decision not in {"accepted","rejected","further_investigation","reviewed"}:return _json_error("Unsupported review decision",400)
        with SessionLocal() as db:
            i=db.get(Incident,incident_id)
            if not i:return _json_error("Incident not found",404)
            db.add(HumanReview(id=str(uuid4()),incident_id=incident_id,decision=body.decision,note=body.note));
            if body.decision=="reviewed":i.status="reviewed"
            db.commit(); return jsonify({"incident_id":incident_id,"decision":body.decision,"status":i.status})
    @app.post("/api/v1/intelligence/lookup")
    def intel_lookup():
        try: body=LookupRequest.model_validate(request.get_json(force=True))
        except (ValidationError,ValueError):return _json_error("Invalid indicator lookup request",400)
        if not body.authorized:return _json_error("Set authorized=true to confirm this public indicator may be disclosed to the configured provider",400)
        try:value=normalize_indicator(body.kind,body.value)
        except IndicatorError as exc:return _json_error(str(exc),400)
        with SessionLocal() as db:
            datasets=db.get(Dataset,body.dataset_id)
            if not datasets:return _json_error("Dataset not found",404)
            cached=(db.query(ThreatIntelResult,Indicator).join(Indicator,ThreatIntelResult.indicator_id==Indicator.id).filter(Indicator.dataset_id==body.dataset_id,Indicator.kind==body.kind,Indicator.value==value,ThreatIntelResult.status.in_(["completed","not_found"]),ThreatIntelResult.retrieved_at>=datetime.now(timezone.utc)-timedelta(hours=24)).order_by(ThreatIntelResult.retrieved_at.desc()).first())
            if cached:
                record,ind=cached; result=dict(record.payload); result.update({"id":record.id,"indicator_id":ind.id,"retrieved_at":record.retrieved_at.isoformat(),"cache_status":"hit"}); return jsonify(result),200
            if settings.intel_provider.lower()=="virustotal": result=lookup_virustotal(body.kind,value,settings.intel_api_key)
            else: result={"provider":"none","status":"not_configured","classification":None,"metrics":None,"error":"Configure THREAT_INTEL_PROVIDER=virustotal and its API key"}
            validation_status={"ip":"public","domain":"valid_syntax","hash":"valid_hash","url":"valid_syntax"}[body.kind]
            ind=Indicator(id=str(uuid4()),dataset_id=datasets.id,kind=body.kind,value=value,validation_status=validation_status,source_event_ids=[]); db.add(ind); db.flush()
            result["cache_status"]="miss"
            record=ThreatIntelResult(id=str(uuid4()),indicator_id=ind.id,provider=result["provider"],status=result["status"],payload=result); db.add(record); db.commit()
            result.update({"id":record.id,"indicator_id":ind.id,"retrieved_at":record.retrieved_at.isoformat()}); return jsonify(result),200
    @app.get("/api/v1/intelligence/results/<result_id>")
    def intel_result(result_id):
        with SessionLocal() as db:
            r=db.get(ThreatIntelResult,result_id)
            if not r:return _json_error("Threat intelligence result not found",404)
            return jsonify({"id":r.id,"indicator_id":r.indicator_id,"provider":r.provider,"status":r.status,"payload":r.payload,"retrieved_at":r.retrieved_at.isoformat()})
    @app.errorhandler(413)
    def too_large(_):return _json_error("Request exceeds configured upload limit",413)
    @app.errorhandler(500)
    def server_error(_):logger.exception("Unhandled request failure"); return _json_error("Internal server error",500)
    return app
