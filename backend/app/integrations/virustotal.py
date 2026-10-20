import hashlib,ipaddress,re
from urllib.parse import quote,urlsplit
import requests

class IndicatorError(ValueError): pass
def normalize_indicator(kind,value):
    value=value.strip()
    if kind=="ip":
        try: ip=ipaddress.ip_address(value)
        except ValueError: raise IndicatorError("Invalid IP address") from None
        if not ip.is_global: raise IndicatorError("Private or reserved IPs must not be sent to external providers")
        return str(ip)
    if kind=="domain":
        value=value.lower().rstrip(".")
        if len(value)>253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",value): raise IndicatorError("Invalid domain name")
        return value
    if kind=="hash":
        if not re.fullmatch(r"(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})",value): raise IndicatorError("Expected an MD5, SHA-1, or SHA-256 hash")
        return value.lower()
    if kind=="url":
        parsed=urlsplit(value)
        if len(value)>2048 or parsed.scheme not in {"http","https"} or not parsed.hostname or parsed.username or parsed.password or any(ch in value for ch in "\r\n"): raise IndicatorError("Only a valid public HTTP/HTTPS URL is supported")
        host=parsed.hostname.lower().rstrip(".")
        if host in {"localhost","metadata.google.internal"} or host.endswith(".local"):raise IndicatorError("Local URLs are not valid external indicators")
        try:
            ip=ipaddress.ip_address(host)
            if not ip.is_global:raise IndicatorError("Private or reserved URL hosts are not supported")
        except ValueError:
            if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",host):raise IndicatorError("Only a valid public HTTP/HTTPS URL is supported")
        return value
    raise IndicatorError("Indicator kind must be ip, domain, hash, or url")
def lookup_virustotal(kind,value,api_key,timeout=8):
    if not api_key: return {"provider":"virustotal","status":"not_configured","classification":None,"metrics":None,"error":"Threat intelligence provider is not configured"}
    normalized=normalize_indicator(kind,value)
    if kind=="url": object_id=__import__('base64').urlsafe_b64encode(normalized.encode()).decode().rstrip("="); path="urls/"+object_id
    elif kind=="ip": path="ip_addresses/"+normalized
    elif kind=="domain": path="domains/"+quote(normalized,safe="")
    else: path="files/"+normalized
    try:
        response=requests.get("https://www.virustotal.com/api/v3/"+path,headers={"x-apikey":api_key,"accept":"application/json"},timeout=(3,timeout),allow_redirects=False)
        if response.status_code==404: return {"provider":"virustotal","status":"not_found","classification":None,"metrics":None,"error":None,"source_reference":response.url}
        response.raise_for_status(); attrs=response.json().get("data",{}).get("attributes",{}); stats=attrs.get("last_analysis_stats",{})
        malicious=int(stats.get("malicious",0)); suspicious=int(stats.get("suspicious",0))
        return {"provider":"virustotal","status":"completed","classification":"provider_reports_detections" if malicious+suspicious else "no_detections_reported","metrics":{"malicious":malicious,"suspicious":suspicious,"undetected":int(stats.get("undetected",0))},"error":None,"source_reference":response.url}
    except requests.Timeout: return {"provider":"virustotal","status":"timeout","classification":None,"metrics":None,"error":"Provider request timed out"}
    except requests.HTTPError as exc:
        status=exc.response.status_code if exc.response is not None else 0
        code="rate_limited" if status==429 else "provider_error"
        return {"provider":"virustotal","status":code,"classification":None,"metrics":None,"error":f"Provider returned HTTP {status}"}
    except (requests.RequestException,ValueError): return {"provider":"virustotal","status":"provider_error","classification":None,"metrics":None,"error":"Provider response was unavailable or invalid"}
