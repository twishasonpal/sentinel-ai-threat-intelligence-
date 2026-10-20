import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.ingestion.parser import parse_bytes
from app.detection.rules import detect
from app.agents.incident_correlator import correlate
from app.agents.quality_controller import validate
from app.integrations.virustotal import normalize_indicator,IndicatorError

def test_parse_jsonl_redacts_secrets_and_normalizes_time():
    events,errors=parse_bytes(b'{"event_id":"x","timestamp":"2025-01-01T00:00:00Z","password":"secret","user":"a"}\n',"x.jsonl",100)
    assert not errors and events[0]["username"]=="a" and "password" not in events[0]["fields"]
    assert events[0]["timestamp"].endswith("+00:00")

def test_parser_rejects_non_ip_source_for_indicator_use():
    events,_=parse_bytes(b'[{"id":"x","source_ip":"localhost"}]',"x.json",10)
    assert events[0]["source_ip"] is None

def test_parser_rejects_duplicate_event_ids_and_oversized_rows():
    events,errors=parse_bytes(b'{"id":"x"}\n{"id":"x"}\n',"x.jsonl",10)
    assert len(events)==1 and any("duplicate event ID" in e for e in errors)
    with __import__('pytest').raises(ValueError):parse_bytes(b'[{"id":1},{"id":2}]',"x.json",1)

def test_deterministic_failed_login_detection_has_event_references():
    events=[{"id":str(i),"timestamp":f"2025-01-01T00:0{i}:00+00:00","event_type":"authentication","username":"person","source_ip":"198.51.100.9","outcome":"failure"} for i in range(5)]
    found=detect(events)
    assert any(x["rule_id"]=="AUTH-001" for x in found)
    assert set(found[0]["event_ids"]).issubset({e["id"] for e in events})

def test_spray_rule_uses_its_documented_time_window():
    events=[{"id":str(i),"timestamp":f"2025-01-01T00:{i*20:02d}:00+00:00","event_type":"authentication","username":f"u{i}","source_ip":"198.51.100.5","outcome":"failure"} for i in range(3)]
    assert "AUTH-002" not in {f["rule_id"] for f in detect(events)}

def test_incident_and_report_quality_links_are_valid():
    events=[{"id":"e1","timestamp":"2025-01-01T00:00:00+00:00","event_type":"authentication","username":"u","source_ip":"203.0.113.10","outcome":"failure"}]
    f={"id":"f1","rule_id":"TEST","title":"test","severity":"low","description":"test","event_ids":["e1"]}
    incidents=correlate(events,[f]); assert len(incidents)==1
    report={"content":{"executive_summary":"summary","severity":"low","timeline":[],"findings":[],"evidence_event_ids":["e1"],"limitations":[]}}
    assert validate(incidents[0],events,[f],report)["passed"]
    report["content"]["evidence_event_ids"]=["fabricated"]
    assert not validate(incidents[0],events,[f],report)["passed"]

def test_incident_correlation_respects_time_window():
    events=[{"id":"e1","timestamp":"2025-01-01T00:00:00+00:00","event_type":"auth","username":"same","source_ip":"203.0.113.10","outcome":"failure"},{"id":"e2","timestamp":"2025-01-01T02:00:00+00:00","event_type":"auth","username":"same","source_ip":"203.0.113.10","outcome":"failure"}]
    findings=[{"id":"f1","title":"a","severity":"low","event_ids":["e1"]},{"id":"f2","title":"b","severity":"low","event_ids":["e2"]}]
    assert len(correlate(events,findings))==2

def test_indicator_validation_blocks_private_ip():
    assert normalize_indicator("ip","8.8.8.8")=="8.8.8.8"
    with __import__('pytest').raises(IndicatorError):normalize_indicator("ip","10.0.0.1")
    with __import__('pytest').raises(IndicatorError):normalize_indicator("url","http://127.0.0.1/admin")
