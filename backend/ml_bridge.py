"""
ML Bridge Adapter: Connects Backend Forensic Pipeline to AI/ML Engine.
Converts backend parsed email format to AI_ML ParsedEmail schema,
invokes EmailAnalyzer, and maps AnalysisResult to frontend-expected JSON shape.
"""

import sys
import os
import logging
import json
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

# Add AI_ML to path for imports
AI_ML_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "AI_ML")
if AI_ML_PATH not in sys.path:
    sys.path.insert(0, AI_ML_PATH)

logger = logging.getLogger("backend.ml_bridge")

# Global analyzer instance (warmed up at startup)
_analyzer = None
_analyzer_loaded = False
_load_error = None


def get_analyzer():
    """
    Get or create the EmailAnalyzer singleton.
    Warms up the model on first call.
    Returns None if ML engine unavailable.
    """
    global _analyzer, _analyzer_loaded, _load_error
    
    if _analyzer_loaded:
        return _analyzer
    
    try:
        from ml.email_analyzer import EmailAnalyzer
        _analyzer = EmailAnalyzer()
        _analyzer.warmup()
        _analyzer_loaded = True
        logger.info("AI/ML EmailAnalyzer warmed up successfully")
        return _analyzer
    except Exception as exc:
        _load_error = exc
        _analyzer_loaded = True
        logger.warning(f"AI/ML EmailAnalyzer unavailable, using rules fallback: {exc}")
        return None


def convert_backend_to_parsed_email(
    email_meta: Any,
    auth_results: Any,
    plain_body: str,
    html_body: str,
    relay_hops: List[Any],
    iocs: Any,
    msg_obj: Any = None
) -> Dict[str, Any]:
    """
    Convert backend parsed email components to AI_ML ParsedEmail schema.
    
    Args:
        email_meta: EmailMetadata from header_parser
        auth_results: AuthResults from header_parser
        plain_body: Plain text body
        html_body: HTML body
        relay_hops: List of RelayHop from relay_parser
        iocs: IOCs from ioc_extractor
        msg_obj: Raw email.message.EmailMessage (optional, for raw headers)
        
    Returns:
        Dict matching AI_ML ParsedEmail schema
    """
    # Build received_chain from relay_hops
    received_chain = []
    for hop in relay_hops:
        received_chain.append({
            "hop": hop.hop_number,
            "from_host": hop.sending_server,
            "from_ip": hop.ip,
            "to_host": hop.receiving_server,
            "timestamp": hop.timestamp,
        })
    
    # Convert auth_results to AI_ML format (lowercase status values)
    auth_results_dict = None
    if auth_results:
        auth_results_dict = {
            "spf": auth_results.spf.value.lower() if auth_results.spf else "none",
            "dkim": auth_results.dkim.value.lower() if auth_results.dkim else "none",
            "dmarc": auth_results.dmarc.value.lower() if auth_results.dmarc else "none",
        }
    
    # Extract raw headers if msg_obj available
    headers_raw = {}
    if msg_obj:
        for key, value in msg_obj.items():
            headers_raw[key] = value
    
    # Extract URLs from IOCs
    urls_in_body = list(iocs.urls) if iocs.urls else []
    
    return {
        "message_id": email_meta.message_id or "",
        "from_address": email_meta.from_address or "",
        "from_display_name": "",
        "reply_to": email_meta.reply_to,
        "to": email_meta.to or [],
        "subject": email_meta.subject or "",
        "body_text": plain_body or "",
        "body_html": html_body,
        "received_chain": received_chain,
        "auth_results": auth_results_dict,
        "headers_raw": headers_raw,
        "urls_in_body": urls_in_body,
        "attachments": [],
    }


def map_analysis_result_to_frontend(
    ml_result: Dict[str, Any],
    email_meta: Any,
    auth_results: Any,
    relay_hops: List[Any],
    iocs: Any,
    ip_intelligence: List[Dict],
    domain_intelligence: List[Dict],
    case_id: str,
    evidence_id: str,
    evidence_hash: str,
    file_name: str,
    file_size: int,
    execution_time_ms: float,
) -> Dict[str, Any]:
    """
    Map AI_ML AnalysisResult to frontend-expected JSON shape (matches MOCK_ANALYSIS).
    
    Frontend shape (from api.js MOCK_ANALYSIS):
    - case_id
    - email: {from, from_address, to, subject, date, message_id, return_path, reply_to, body_preview}
    - headers: {from, to, subject, date, message_id, return_path, reply_to}
    - authentication: {spf: {status, detail}, dkim: {status, detail}, dmarc: {status, detail}}
    - relay_path: [{hop_number, ip, ip_type, from_host, by_host, delay_seconds, lat, lng}]
    - iocs: {urls, domains, ip_addresses, email_addresses}
    - risk: {score, classification, scoring_type, signals: [{signal, severity, category, weight}], ml_signals: {phishing_probability, bec_probability, model_name, confidence}}
    - metadata: {case_id, evidence_id, analysis_timestamp, file_name, file_size_bytes, execution_time_ms, parser_version, evidence_hash}
    """
    analysis_ts = datetime.now(timezone.utc).isoformat()
    
    # Build email object (frontend expects both 'from' display+address and 'from_address')
    from_display = ""
    from_addr = email_meta.from_address or ""
    if email_meta.from_address and hasattr(email_meta, 'from') and email_meta.from_address:
        # Try to extract display name from raw header if available
        from_display = email_meta.from_address
    
    email_obj = {
        "from": f'"{from_display}" <{from_addr}>' if from_display else from_addr,
        "from_address": from_addr,
        "to": email_meta.to or [],
        "subject": email_meta.subject or "",
        "date": email_meta.date or analysis_ts,
        "message_id": email_meta.message_id or "",
        "return_path": email_meta.return_path or "",
        "reply_to": email_meta.reply_to or "",
        "body_preview": email_meta.body_preview or (plain_body[:500] + "..." if len(plain_body) > 500 else plain_body) if 'plain_body' in locals() else "",
    }
    
    # Build headers object (subset for display)
    headers_obj = {
        "from": email_obj["from"],
        "to": ", ".join(email_meta.to) if email_meta.to else "",
        "subject": email_meta.subject or "",
        "date": email_meta.date or analysis_ts,
        "message_id": email_meta.message_id or "",
        "return_path": email_meta.return_path or "",
        "reply_to": email_meta.reply_to or "",
    }
    
    # Build authentication object with detail fields
    def get_auth_detail(auth_obj, field):
        if auth_obj and auth_obj.details:
            return auth_obj.details.get(f"{field}_auth_result") or auth_obj.details.get(f"received_{field}_header") or ""
        return ""
    
    auth_obj = {
        "spf": {
            "status": auth_results.spf.value if auth_results and auth_results.spf else "UNKNOWN",
            "detail": get_auth_detail(auth_results, "spf") or "No SPF authentication header present"
        },
        "dkim": {
            "status": auth_results.dkim.value if auth_results and auth_results.dkim else "UNKNOWN",
            "detail": get_auth_detail(auth_results, "dkim") or "No DKIM signature verified"
        },
        "dmarc": {
            "status": auth_results.dmarc.value if auth_results and auth_results.dmarc else "UNKNOWN",
            "detail": get_auth_detail(auth_results, "dmarc") or "No DMARC policy enforcement header"
        },
    }
    
    # Build relay_path with geo coordinates (lat/lng from ip_intelligence)
    ip_geo_map = {}
    for ip_intel in ip_intelligence:
        if ip_intel.get("ip") and ip_intel.get("lat") is not None and ip_intel.get("lng") is not None:
            ip_geo_map[ip_intel["ip"]] = {"lat": ip_intel["lat"], "lng": ip_intel["lng"]}
    
    relay_path = []
    for hop in relay_hops:
        geo = ip_geo_map.get(hop.ip, {"lat": 0, "lng": 0})
        relay_path.append({
            "hop_number": hop.hop_number,
            "ip": hop.ip or "",
            "ip_type": hop.ip_type or "unknown",
            "from_host": hop.sending_server or "",
            "by_host": hop.receiving_server or "",
            "delay_seconds": hop.delay_seconds or 0,
            "lat": geo.get("lat", 0),
            "lng": geo.get("lng", 0),
        })
    
    # Build IOCs in frontend format
    iocs_obj = {
        "urls": list(iocs.urls) if iocs.urls else [],
        "domains": list(iocs.domains) if iocs.domains else [],
        "ip_addresses": list(iocs.ips) if iocs.ips else [],
        "email_addresses": list(iocs.emails) if iocs.emails else [],
    }
    
    # Map ML signals to frontend risk format
    fraud_score = ml_result.get("fraud_score", 50)
    risk_level = ml_result.get("risk_level", "MEDIUM")
    classification = ml_result.get("classification", {})
    tower_scores = ml_result.get("tower_scores", {})
    reasons = ml_result.get("reasons", [])
    flagged_spans = ml_result.get("text_analysis", {}).get("flagged_spans", [])
    ml_iocs = ml_result.get("iocs", {})
    model_metadata = ml_result.get("model_metadata", {})
    
    # Determine classification label for frontend
    label_map = {
        "LOW": "LOW RISK",
        "MEDIUM": "MEDIUM RISK",
        "HIGH": "HIGH RISK",
        "CRITICAL": "CRITICAL RISK",
    }
    frontend_classification = label_map.get(risk_level, "MEDIUM RISK")
    
    # Build signals in frontend format
    signals = []
    for reason in reasons:
        signals.append({
            "signal": reason.get("text", "ML-detected threat signal"),
            "severity": reason.get("severity", "MEDIUM"),
            "category": "ML Detection",
            "weight": 10,
        })
    
    # Add tower scores as signals
    if tower_scores.get("text", 0) > 30:
        signals.append({
            "signal": "High phishing probability in text content",
            "severity": "HIGH",
            "category": "NLP Analysis",
            "weight": int(tower_scores.get("text", 0)),
        })
    if tower_scores.get("url", 0) > 30:
        signals.append({
            "signal": "Suspicious URLs detected",
            "severity": "HIGH",
            "category": "URL Analysis",
            "weight": int(tower_scores.get("url", 0)),
        })
    if tower_scores.get("header", 0) > 30:
        signals.append({
            "signal": "Email header anomalies detected",
            "severity": "MEDIUM",
            "category": "Header Analysis",
            "weight": int(tower_scores.get("header", 0)),
        })
    
    # Build ml_signals for frontend
    phishing_prob = classification.get("all_scores", {}).get("PHISHING", 0)
    bec_prob = classification.get("all_scores", {}).get("BEC_PAYMENT_DIVERSION", 0)
    if bec_prob == 0:
        bec_prob = classification.get("all_scores", {}).get("IMPERSONATION", 0)
    
    ml_signals = {
        "phishing_probability": phishing_prob,
        "bec_probability": bec_prob,
        "model_name": "ThreatLens-DistilBERT-v1",
        "confidence": classification.get("confidence", 0.5),
    }
    
    # Build metadata
    metadata = {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "analysis_timestamp": analysis_ts,
        "file_name": file_name,
        "file_size_bytes": file_size,
        "execution_time_ms": execution_time_ms,
        "parser_version": "1.0.0-ml-integrated",
        "evidence_hash": evidence_hash,
    }
    
    return {
        "case_id": case_id,
        "email": email_obj,
        "headers": headers_obj,
        "authentication": auth_obj,
        "relay_path": relay_path,
        "iocs": iocs_obj,
        "risk": {
            "score": int(fraud_score),
            "classification": frontend_classification,
            "scoring_type": "AI/ML Fusion: DistilBERT + Rules",
            "signals": signals,
            "ml_signals": ml_signals,
        },
        "metadata": metadata,
    }


def create_fallback_analysis(
    email_meta: Any,
    auth_results: Any,
    relay_hops: List[Any],
    iocs: Any,
    ip_intelligence: List[Dict],
    plain_body: str,
    case_id: str,
    evidence_id: str,
    evidence_hash: str,
    file_name: str,
    file_size: int,
    execution_time_ms: float,
    backend_risk: Any,
) -> Dict[str, Any]:
    """
    Create frontend-shaped response using backend deterministic risk engine
    when AI/ML engine is unavailable.
    """
    analysis_ts = datetime.now(timezone.utc).isoformat()
    
    # Build email object
    email_obj = {
        "from": f'"{email_meta.from_address}" <{email_meta.from_address}>' if email_meta.from_address else "",
        "from_address": email_meta.from_address or "",
        "to": email_meta.to or [],
        "subject": email_meta.subject or "",
        "date": email_meta.date or analysis_ts,
        "message_id": email_meta.message_id or "",
        "return_path": email_meta.return_path or "",
        "reply_to": email_meta.reply_to or "",
        "body_preview": email_meta.body_preview or (plain_body[:500] + "..." if len(plain_body) > 500 else plain_body),
    }
    
    headers_obj = {
        "from": email_obj["from"],
        "to": ", ".join(email_meta.to) if email_meta.to else "",
        "subject": email_meta.subject or "",
        "date": email_meta.date or analysis_ts,
        "message_id": email_meta.message_id or "",
        "return_path": email_meta.return_path or "",
        "reply_to": email_meta.reply_to or "",
    }
    
    def get_auth_detail(auth_obj, field):
        if auth_obj and auth_obj.details:
            return auth_obj.details.get(f"{field}_auth_result") or auth_obj.details.get(f"received_{field}_header") or ""
        return ""
    
    auth_obj = {
        "spf": {
            "status": auth_results.spf.value if auth_results and auth_results.spf else "UNKNOWN",
            "detail": get_auth_detail(auth_results, "spf") or "No SPF authentication header present"
        },
        "dkim": {
            "status": auth_results.dkim.value if auth_results and auth_results.dkim else "UNKNOWN",
            "detail": get_auth_detail(auth_results, "dkim") or "No DKIM signature verified"
        },
        "dmarc": {
            "status": auth_results.dmarc.value if auth_results and auth_results.dmarc else "UNKNOWN",
            "detail": get_auth_detail(auth_results, "dmarc") or "No DMARC policy enforcement header"
        },
    }
    
    ip_geo_map = {}
    for ip_intel in ip_intelligence:
        if ip_intel.get("ip") and ip_intel.get("lat") is not None and ip_intel.get("lng") is not None:
            ip_geo_map[ip_intel["ip"]] = {"lat": ip_intel["lat"], "lng": ip_intel["lng"]}
    
    relay_path = []
    for hop in relay_hops:
        geo = ip_geo_map.get(hop.ip, {"lat": 0, "lng": 0})
        relay_path.append({
            "hop_number": hop.hop_number,
            "ip": hop.ip or "",
            "ip_type": hop.ip_type or "unknown",
            "from_host": hop.sending_server or "",
            "by_host": hop.receiving_server or "",
            "delay_seconds": hop.delay_seconds or 0,
            "lat": geo.get("lat", 0),
            "lng": geo.get("lng", 0),
        })
    
    iocs_obj = {
        "urls": list(iocs.urls) if iocs.urls else [],
        "domains": list(iocs.domains) if iocs.domains else [],
        "ip_addresses": list(iocs.ips) if iocs.ips else [],
        "email_addresses": list(iocs.emails) if iocs.emails else [],
    }
    
    # Use backend risk engine signals
    signals = []
    for signal in backend_risk.signals:
        signals.append({
            "signal": signal.name,
            "severity": signal.severity,
            "category": "Forensic Rules",
            "weight": signal.score_impact,
        })
    
    ml_signals = {
        "phishing_probability": 0.0,
        "bec_probability": 0.0,
        "model_name": "ThreatLens-Rules-v1",
        "confidence": 0.0,
    }
    
    metadata = {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "analysis_timestamp": analysis_ts,
        "file_name": file_name,
        "file_size_bytes": file_size,
        "execution_time_ms": execution_time_ms,
        "parser_version": "1.0.0-rules-fallback",
        "evidence_hash": evidence_hash,
    }
    
    return {
        "case_id": case_id,
        "email": email_obj,
        "headers": headers_obj,
        "authentication": auth_obj,
        "relay_path": relay_path,
        "iocs": iocs_obj,
        "risk": {
            "score": backend_risk.score,
            "classification": backend_risk.classification.value,
            "scoring_type": "Deterministic Rule Pipeline (ML Fallback)",
            "signals": signals,
            "ml_signals": ml_signals,
        },
        "metadata": metadata,
    }


def analyze_with_ml(
    email_meta: Any,
    auth_results: Any,
    plain_body: str,
    html_body: str,
    relay_hops: List[Any],
    iocs: Any,
    ip_intelligence: List[Dict],
    domain_intelligence: List[Dict],
    case_id: str,
    evidence_id: str,
    evidence_hash: str,
    file_name: str,
    file_size: int,
    execution_time_ms: float,
    msg_obj: Any = None,
) -> Dict[str, Any]:
    """
    Main entry point: Try ML analysis, fallback to rules on any failure.
    Returns frontend-shaped JSON.
    """
    analyzer = get_analyzer()
    
    if analyzer is None:
        # ML unavailable - use fallback
        logger.info("Using rules fallback (ML engine not loaded)")
        from risk_engine import calculate_risk
        backend_risk = calculate_risk(
            email_meta=email_meta,
            auth=auth_results,
            iocs=iocs,
            relay_hops=relay_hops,
            plain_body=plain_body,
        )
        return create_fallback_analysis(
            email_meta=email_meta,
            auth_results=auth_results,
            relay_hops=relay_hops,
            iocs=iocs,
            ip_intelligence=ip_intelligence,
            plain_body=plain_body,
            case_id=case_id,
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            file_name=file_name,
            file_size=file_size,
            execution_time_ms=execution_time_ms,
            backend_risk=backend_risk,
        )
    
    try:
        # Convert to AI_ML ParsedEmail format
        parsed_email = convert_backend_to_parsed_email(
            email_meta=email_meta,
            auth_results=auth_results,
            plain_body=plain_body,
            html_body=html_body,
            relay_hops=relay_hops,
            iocs=iocs,
            msg_obj=msg_obj,
        )
        
        # Run ML analysis
        ml_result = analyzer.analyze_email(parsed_email)
        
        # Map to frontend shape
        return map_analysis_result_to_frontend(
            ml_result=ml_result,
            email_meta=email_meta,
            auth_results=auth_results,
            relay_hops=relay_hops,
            iocs=iocs,
            ip_intelligence=ip_intelligence,
            domain_intelligence=domain_intelligence,
            case_id=case_id,
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            file_name=file_name,
            file_size=file_size,
            execution_time_ms=execution_time_ms,
        )
    except Exception as exc:
        logger.error(f"ML analysis failed, falling back to rules: {exc}", exc_info=True)
        from risk_engine import calculate_risk
        backend_risk = calculate_risk(
            email_meta=email_meta,
            auth=auth_results,
            iocs=iocs,
            relay_hops=relay_hops,
            plain_body=plain_body,
        )
        return create_fallback_analysis(
            email_meta=email_meta,
            auth_results=auth_results,
            relay_hops=relay_hops,
            iocs=iocs,
            ip_intelligence=ip_intelligence,
            plain_body=plain_body,
            case_id=case_id,
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            file_name=file_name,
            file_size=file_size,
            execution_time_ms=execution_time_ms,
            backend_risk=backend_risk,
        )


# Warm up on module import (optional, can be called explicitly at startup)
def warmup():
    """Explicit warmup call for application startup."""
    get_analyzer()