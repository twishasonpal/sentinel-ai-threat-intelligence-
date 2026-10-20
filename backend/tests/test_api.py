import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import create_app

def test_health_upload_and_background_analysis():
    client=create_app({"TESTING":True}).test_client()
    assert client.get("/api/v1/health").json["status"]=="ok"
    response=client.post("/api/v1/datasets/sample")
    assert response.status_code==201
    dataset_id=response.json["id"]
    started=client.post(f"/api/v1/datasets/{dataset_id}/analyze")
    assert started.status_code==202
    job_id=started.json["id"]
    import time
    for _ in range(100):
        status=client.get(f"/api/v1/jobs/{job_id}").json
        if status["status"] not in ("queued","running"):break
        time.sleep(.03)
    assert status["status"] in ("completed","completed_with_warnings")
    assert client.get(f"/api/v1/datasets/{dataset_id}/findings").json
    assert client.get("/api/v1/incidents").json

def test_upload_validation_and_intel_requires_explicit_permission():
    client=create_app({"TESTING":True}).test_client()
    response=client.post("/api/v1/datasets",data={"file":(__import__('io').BytesIO(b"bad"),"data.exe")})
    assert response.status_code==400
    response=client.post("/api/v1/intelligence/lookup",json={"kind":"ip","value":"8.8.8.8","authorized":False})
    assert response.status_code==400

def test_explicit_intel_lookup_is_cached(monkeypatch):
    from dataclasses import replace
    import app as app_module
    client=create_app({"TESTING":True}).test_client()
    dataset=client.post("/api/v1/datasets/sample").json
    monkeypatch.setattr(app_module,"settings",replace(app_module.settings,intel_provider="virustotal",intel_api_key="test-key"))
    calls=[]
    def fake_lookup(kind,value,key):
        calls.append(value);return {"provider":"virustotal","status":"completed","classification":"provider_reports_detections","metrics":{"malicious":1,"suspicious":0},"error":None}
    monkeypatch.setattr(app_module,"lookup_virustotal",fake_lookup)
    body={"dataset_id":dataset["id"],"kind":"ip","value":"8.8.8.8","authorized":True}
    first=client.post("/api/v1/intelligence/lookup",json=body).json
    second=client.post("/api/v1/intelligence/lookup",json=body).json
    assert first["cache_status"]=="miss" and second["cache_status"]=="hit" and len(calls)==1
