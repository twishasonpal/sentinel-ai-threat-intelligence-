from typing import TypedDict
class AnalysisState(TypedDict,total=False):
    job_id:str
    events:list[dict]
    findings:list[dict]
    log_summary:dict
    indicators:list[dict]
    anomalies:dict
    incidents:list[dict]
    investigations:list[dict]
    reports:list[dict]
    quality:list[dict]
    ai_advice:dict
