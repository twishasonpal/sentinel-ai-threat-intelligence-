from langgraph.graph import StateGraph,START,END
from .state import AnalysisState
from ..detection.rules import detect
from ..agents import log_analyzer,threat_intelligence,anomaly_analyzer,incident_correlator,investigator,report_generator,quality_controller,ai_advisor

def build_graph():
    def detections(s): return {"findings":detect(s["events"])}
    def log_analysis(s): return {"log_summary":log_analyzer.run(s["events"],s["findings"])}
    def intel(s): return {"indicators":threat_intelligence.extract(s["events"])}
    def anomaly(s): return {"anomalies":anomaly_analyzer.run(s["events"])}
    def correlation(s): return {"incidents":incident_correlator.correlate(s["events"],s["findings"])}
    def investigation(s):
        incs=[]
        for inc in s.get("incidents",[]):
            inv=investigator.run(inc,s["findings"],s["log_summary"])
            inc["summary"]=inv["evidence_summary"]; incs.append(inv)
        ai=ai_advisor.advise({"event_count":len(s["events"]),"findings":s["findings"],"incidents":[{"id":i["id"],"severity":i["severity"],"event_ids":i["event_ids"]} for i in s.get("incidents",[])]})
        for inv in incs:
            if ai.get("status")=="completed": inv["ai_summary"]={"notes":ai["notes"],"questions":ai["questions"]}
        return {"investigations":incs,"ai_advice":ai}
    def reports(s): return {"reports":[report_generator.run(i,s["findings"],s["events"],inv) for i,inv in zip(s.get("incidents",[]),s.get("investigations",[]))]}
    def quality(s): return {"quality":[quality_controller.validate(i,s["events"],s["findings"],r) for i,r in zip(s.get("incidents",[]),s.get("reports",[]))]}
    g=StateGraph(AnalysisState)
    for n,f in [("detect",detections),("log_analysis",log_analysis),("threat_intelligence",intel),("anomaly_analysis",anomaly),("correlation",correlation),("investigation",investigation),("report_generation",reports),("quality_control",quality)]: g.add_node(n,f)
    g.add_edge(START,"detect"); g.add_edge("detect","log_analysis"); g.add_edge("log_analysis","threat_intelligence"); g.add_edge("threat_intelligence","anomaly_analysis"); g.add_edge("anomaly_analysis","correlation"); g.add_edge("correlation","investigation"); g.add_edge("investigation","report_generation"); g.add_edge("report_generation","quality_control"); g.add_edge("quality_control",END)
    return g.compile()
workflow=build_graph()
