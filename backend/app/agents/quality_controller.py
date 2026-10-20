def validate(incident,events,findings,report):
    event_ids={e["id"] for e in events}; finding_ids={f["id"] for f in findings}
    bad_events=[x for x in incident["event_ids"] if x not in event_ids]
    bad_findings=[x for x in incident["finding_ids"] if x not in finding_ids]
    report_events=[x for x in report["content"]["evidence_event_ids"] if x not in event_ids]
    required={"executive_summary","severity","timeline","findings","evidence_event_ids","limitations"}
    missing=sorted(required-set(report["content"]))
    return {"passed":not (bad_events or bad_findings or report_events or missing),"unknown_event_ids":bad_events+report_events,"unknown_finding_ids":bad_findings,"missing_report_fields":missing}
