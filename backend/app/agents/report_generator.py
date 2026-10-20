def run(incident,findings,events,investigation,reviews=None):
    byid={e["id"]:e for e in events}; related=[byid[x] for x in incident["event_ids"] if x in byid]
    fs=[f for f in findings if f["id"] in incident["finding_ids"]]
    content={"executive_summary":incident["summary"],"severity":incident["severity"],"severity_rationale":"Severity is the maximum deterministic rule severity among linked findings.","timeline":incident["timeline"],"findings":[{"rule_id":f["rule_id"],"title":f["title"],"severity":f["severity"],"event_ids":f["event_ids"],"description":f["description"]} for f in fs],"evidence_event_ids":[e["id"] for e in related],"indicators":incident["indicators"],"alternative_explanations":investigation["alternative_explanations"],"recommended_next_steps":investigation["recommended_steps"],"ai_assistant_notes":{"status":"unavailable","notes":[]} if not investigation.get("ai_summary") else {"status":"unverified_advisory","notes":investigation["ai_summary"]},"limitations":["This report summarizes supplied telemetry only.","Anomaly signals and AI explanations are not proof of compromise.","No response actions were executed by this platform."],"human_review":reviews or []}
    lines=["# Incident report", "",f"**Severity:** {incident['severity'].upper()}  ",f"**Status:** {incident['status']}","", "## Executive summary",content["executive_summary"],"", "## Evidence and findings"]
    lines += [f"- `{f['rule_id']}` ({f['severity']}): {f['title']} — event IDs: {', '.join(f['event_ids'])}" for f in content["findings"]] or ["- No deterministic findings linked."]
    lines += ["", "## Timeline"]+[f"- {e['timestamp']} · {e['event_type']} · event `{e['id']}` · user {e.get('username') or 'unknown'} · source {e.get('source_ip') or 'unknown'}" for e in related]
    lines += ["", "## AI assistant notes (unverified)"]+[f"- {x}" for x in content["ai_assistant_notes"].get("notes",[])] if content["ai_assistant_notes"].get("notes") else ["", "## AI assistant notes (unverified)", "- No AI notes were available."]
    lines += ["", "## Alternative explanations"]+[f"- {x}" for x in content["alternative_explanations"]]
    lines += ["", "## Recommended defensive next steps"]+[f"- {x}" for x in content["recommended_next_steps"]]
    lines += ["", "## Limitations"]+[f"- {x}" for x in content["limitations"]]
    return {"content":content,"markdown":"\n".join(lines)}
