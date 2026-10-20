import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"backend"))
from app.ingestion.parser import parse_bytes
from app.detection.rules import detect
from app.agents.incident_correlator import correlate
from app.agents.report_generator import run as make_report
from app.agents.investigator import run as investigate
from app.agents.log_analyzer import run as log_summary
from app.agents.quality_controller import validate

events,_=parse_bytes((ROOT/"sample_data/auth_events.jsonl").read_bytes(),"auth_events.jsonl",100)
for e in events:e["id"]=e["event_key"]
expected=json.loads((ROOT/"evals/fixtures/expected.json").read_text(encoding="utf-8"))
findings=detect(events); predicted={f["rule_id"] for f in findings}; truth=set(expected["expected_rule_ids"])
tp=len(predicted&truth); fp=len(predicted-truth); fn=len(truth-predicted)
precision=tp/(tp+fp) if tp+fp else 0.0; recall=tp/(tp+fn) if tp+fn else 0.0; f1=2*precision*recall/(precision+recall) if precision+recall else 0.0
incidents=correlate(events,findings); expected_ids=set(expected["expected_incident_event_ids"])
linked=set(x for i in incidents for x in i["event_ids"]); incident_coverage=len(expected_ids&linked)/len(expected_ids) if expected_ids else 0
benign_ids=set(expected["benign_event_ids"]); benign_alerted={x for f in findings for x in f["event_ids"] if x in benign_ids}; benign_fpr=len(benign_alerted)/len(benign_ids) if benign_ids else 0
report_checks=[]
for incident in incidents:
    inv=investigate(incident,findings,log_summary(events,findings)); incident["summary"]=inv["evidence_summary"]; report=make_report(incident,findings,events,inv); report_checks.append(validate(incident,events,findings,report)["passed"])
report={"dataset":"synthetic authentication events","event_count":len(events),"expected_rule_ids":sorted(truth),"predicted_rule_ids":sorted(predicted),"rule_metrics":{"true_positive":tp,"false_positive":fp,"false_negative":fn,"precision":precision,"precision_denominator":"TP + FP","recall":recall,"recall_denominator":"TP + FN","f1":f1},"benign_event_false_positive_rate":{"alerted_benign_events":len(benign_alerted),"labelled_benign_events":len(benign_ids),"ratio":benign_fpr},"expected_event_incident_coverage":{"covered_events":len(expected_ids&linked),"expected_events":len(expected_ids),"ratio":incident_coverage},"report_reference_validity":{"passed_reports":sum(report_checks),"total_reports":len(report_checks)},"limitations":"One small synthetic dataset only; fixture results are plumbing checks, not estimates of enterprise detection performance."}
(ROOT/"evals/results.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
lines=["# SentinelAI evaluation results","",f"Events evaluated: {len(events)}","",f"Rule precision: {precision:.2%} (TP / (TP + FP))",f"Rule recall: {recall:.2%} (TP / (TP + FN))",f"Rule F1: {f1:.2%}",f"Benign event false-positive rate: {benign_fpr:.2%} (benign events linked to a finding / labelled benign events)",f"Expected incident event coverage: {len(expected_ids&linked)}/{len(expected_ids)}",f"Report reference checks passed: {sum(report_checks)}/{len(report_checks)}","",report["limitations"],""]
(ROOT/"evals/REPORT.md").write_text("\n".join(lines),encoding="utf-8")
print(json.dumps(report,indent=2))
