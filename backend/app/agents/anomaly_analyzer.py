from collections import Counter
def run(events,ml_enabled=False):
    counts=Counter(e.get("source_ip") for e in events if e.get("source_ip")); baseline=(len(events)/max(len(counts),1))
    unusual=[{"source_ip":ip,"event_count":count,"baseline_mean":round(baseline,2),"score":round(count/max(baseline,1),2),"interpretation":"unusually frequent relative to this dataset; anomaly is not proof of malicious activity"} for ip,count in counts.items() if count>=max(5,baseline*3)]
    return {"method":"frequency baseline","ml_enabled":False,"anomalies":unusual,"note":"Scores are relative frequency ratios, not probabilities of maliciousness."}
