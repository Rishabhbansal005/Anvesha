"""
ANVESH Real Email Forensic Ingestion & Parser Engine.
Deterministic RFC-822 analysis, Received hop traversal, cryptographic authentication check,
observable extraction, and direct persistence to Supabase.
"""
import email
import hashlib
import ipaddress
import re
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Request
from pydantic import BaseModel
from app.database.supabase_client import supabase
from app.services.risk_engine import risk_engine, ml_classifier
from app.services.intelligence_service import intelligence_service
from app.services.intelligence.ip_enrichment import ip_enrichment_service
from app.services.attribution_service import attribution_service
from app.services.lookalike_service import lookalike_service
from app.services.identity_impersonation_service import identity_impersonation_service
from app.services.campaign_service import campaign_service
from app.services.forensic_fusion_service import forensic_fusion_service
from app.services.disposable_email_service import disposable_email_service
from app.schemas.identity import IdentityImpersonationRequest
from app.schemas.fusion import ForensicFusionRequest
from app.schemas.disposable import DisposableCheckRequest

router = APIRouter()

MAX_EMAIL_BYTES = 10 * 1024 * 1024  # 10 MB limit for untrusted email uploads


class EmailSubmission(BaseModel):
    raw_content: Optional[str] = None
    raw_eml: Optional[str] = None
    file_name: Optional[str] = "submitted_email.eml"


class LookalikeDetectionRequest(BaseModel):
    candidate_domain: str
    trusted_domain: Optional[str] = None


@router.post("/lookalike-detect")
async def detect_lookalike_endpoint(req: LookalikeDetectionRequest):
    """
    Model 3B (lookalike_domain_v1) Lookalike & Brand Impersonation Detection.
    Tier 1 Deterministic Security Invariants -> Tier 2 Random Forest Structural Model.
    Provides infrastructure similarity evidence; does NOT establish attacker identity.
    """
    if not req.candidate_domain:
        raise HTTPException(status_code=400, detail="candidate_domain is required")
    return lookalike_service.detect_lookalike(
        candidate_domain=req.candidate_domain,
        trusted_domain=req.trusted_domain
    )


@router.post("/identity-impersonation-detect", summary="Model 3A Identity & Header Impersonation Detection")
async def detect_identity_impersonation_endpoint(req: IdentityImpersonationRequest):
    """
    Model 3A (model3a_deterministic_v1) Identity & Header Impersonation Detection.
    Evaluates executive display-name spoofing, Reply-To mismatch, and header discrepancies.
    Provides technical discrepancy evidence; does NOT establish attacker identity.
    """
    sender = f"{req.sender_name} <{req.sender_email}>" if req.sender_name and req.sender_email else (req.sender_email or req.sender_name or "")
    if not sender:
        raise HTTPException(status_code=400, detail="sender_name or sender_email is required")

    trusted_dict = req.trusted_identity.model_dump() if req.trusted_identity else None
    return identity_impersonation_service.evaluate(
        sender_header=sender,
        reply_to_header=req.reply_to,
        trusted_identity=trusted_dict,
        model3b_result=req.model3b_result,
        auth_context=req.auth_context
    )


@router.post("/forensic-fusion", summary="Cross-Modal Threat Correlation & Forensic Signal Fusion (Phase 9B)")
async def forensic_fusion_endpoint(req: ForensicFusionRequest):
    """
    Synthesizes multi-modal evidence (NLP, BEC, Identity M3A, Lookalike M3B, Auth, Transport, Threat Intel, Campaign)
    using explainable category scoring and explicit anti-double-counting invariants.
    Strict Non-Attribution Boundary: Actor Identity is NOT ESTABLISHED.
    """
    return forensic_fusion_service.fuse(
        ml_signal=req.ml_signal,
        behavior_signal=req.behavior_signal,
        identity_impersonation=req.identity_impersonation,
        lookalike_evidence=req.lookalike_evidence,
        auth_context=req.auth_context,
        transport_evidence=req.transport_evidence,
        threat_intel=req.threat_intel,
        campaign=req.campaign,
        evidence_gaps=req.evidence_gaps,
        disposable_evidence=req.disposable_evidence,
    )


@router.post("/disposable-intelligence", summary="Disposable & Temporary Email Intelligence Lookup (Phase 12.5)")
async def detect_disposable_email_endpoint(req: DisposableCheckRequest):
    """
    Evaluates whether an email address or domain belongs to a known disposable/temporary provider
    or a legitimate privacy forwarding service (Apple, Mozilla, SimpleLogin, etc.).
    Returns deterministic classification, provider metadata, and cryptographic dataset SHA-256.
    """
    target = req.email or req.domain
    if not target:
        raise HTTPException(status_code=400, detail="email or domain is required")
    if req.email:
        return disposable_email_service.classify_sender(req.email)
    return disposable_email_service.classify_domain(req.domain)


def extract_ips_from_text(text: str) -> List[str]:
    # Match both IPv4 and standard IPv6 notations
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'
    matches = re.findall(ipv4_pattern, text) + re.findall(ipv6_pattern, text)
    valid_ips = []
    for m in matches:
        try:
            ip_obj = ipaddress.ip_address(m)
            canonical = str(ip_obj)
            if canonical not in valid_ips:
                valid_ips.append(canonical)
        except ValueError:
            pass
    return valid_ips


def is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved)
    except ValueError:
        return False


def extract_domains_from_text(text: str) -> List[str]:
    pattern = r'@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})'
    domains = re.findall(pattern, text)
    unique_domains = []
    for d in domains:
        clean = d.strip().lower()
        if clean not in unique_domains and "." in clean:
            unique_domains.append(clean)
    return unique_domains


def extract_urls_from_text(text: str) -> List[str]:
    pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(pattern, text)
    unique_urls = []
    for u in urls:
        clean = u.strip()
        if clean not in unique_urls:
            unique_urls.append(clean)
    return unique_urls[:20]  # Limit to 20 for safety


def sanitize_evidence_filename(raw_name: Optional[str]) -> str:
    r"""
    Sanitizes untrusted filenames from client uploads:
    - Rejects null bytes (\x00)
    - Neutralizes path traversal sequences (../, ..\)
    - Rejects dangerous executable/script extensions
    - Generates safe server-normalized filename
    """
    if not raw_name:
        return f"evidence_{uuid.uuid4().hex[:8]}.eml"
    
    if "\x00" in raw_name:
        raise HTTPException(status_code=400, detail="Invalid filename: null bytes detected")
    
    if ".." in raw_name or "/" in raw_name or "\\" in raw_name:
        # Detect traversal attempt and isolate safe basename
        base_name = raw_name.replace("\\", "/").split("/")[-1]
        base_name = re.sub(r'\.+', '.', base_name).strip(".")
    else:
        base_name = raw_name.strip()

    # Reject dangerous executable/script extensions
    dangerous_extensions = (
        ".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".js", ".py",
        ".php", ".jar", ".msi", ".dll", ".so", ".bin", ".scr"
    )
    if any(base_name.lower().endswith(d_ext) for d_ext in dangerous_extensions):
        raise HTTPException(
            status_code=400,
            detail=f"Security violation: Executable or script file '{base_name}' is not allowed for forensic email ingestion."
        )

    clean = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', base_name)
    if not clean or clean.startswith("."):
        clean = f"evidence_{uuid.uuid4().hex[:8]}.eml"

    return clean


@router.post("/analyze", summary="Analyze Real Suspicious Email (.eml or raw text)")
async def analyze_email(
    request: Request,
    file: Optional[UploadFile] = File(None),
    raw_headers: Optional[str] = Form(None)
):
    """
    Forensic ingestion pipeline:
    1. Reads raw bytes, enforces 10MB limit, computes SHA-256 evidence fingerprint.
    2. Parses RFC-822 headers: From, To, Subject, Reply-To, Return-Path, Message-ID.
    3. Reconstructs Received header sequence and isolates earliest reliable public IP.
    4. Evaluates SPF, DKIM, and DMARC status.
    5. Extracts observables (IPs, domains, URLs, hashes).
    6. Calculates normalized 0-100 risk score.
    7. Persists Case, Email, Observables, and Evidence records to Supabase.
    """
    raw_text = ""
    file_name = "analyzed_message.eml"
    file_size = 0

    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
            raw_text = body.get("raw_eml") or body.get("raw_content") or body.get("raw_headers") or ""
            file_name = sanitize_evidence_filename(body.get("file_name", "submitted_message.eml"))
            file_size = len(raw_text.encode('utf-8'))
        except HTTPException:
            raise
        except Exception:
            pass
    elif file:
        file_name = sanitize_evidence_filename(file.filename)
        file_bytes = await file.read(MAX_EMAIL_BYTES + 1)
        file_size = len(file_bytes)
        if file_size > MAX_EMAIL_BYTES:
            raise HTTPException(status_code=413, detail=f"Email file exceeds maximum size limit of {MAX_EMAIL_BYTES // (1024*1024)}MB.")
        try:
            raw_text = file_bytes.decode('utf-8', errors='replace')
        except Exception:
            raw_text = str(file_bytes)
    elif raw_headers:
        raw_text = raw_headers
        file_name = "pasted_headers.txt"
        file_size = len(raw_headers.encode('utf-8'))

    if file_size > MAX_EMAIL_BYTES:
        raise HTTPException(status_code=413, detail="Email payload exceeds maximum allowed size.")

    if not raw_text.strip():
        raise HTTPException(status_code=400, detail="No email content or headers provided.")

    # 1. SHA-256 Fingerprint from actual input
    sha256_hash = hashlib.sha256(raw_text.encode('utf-8')).hexdigest()

    # 2. RFC-822 Header Parsing
    from email.header import decode_header

    def _decode_header_val(val: Optional[str]) -> str:
        if not val:
            return ""
        try:
            parts = decode_header(val)
            decoded = []
            for part, enc in parts:
                if isinstance(part, bytes):
                    decoded.append(part.decode(enc or 'utf-8', errors='replace'))
                else:
                    decoded.append(str(part))
            return "".join(decoded).strip()
        except Exception:
            return str(val)

    msg = email.message_from_string(raw_text)
    subject = _decode_header_val(msg.get("Subject", "(No Subject)"))
    sender = _decode_header_val(msg.get("From", "Unknown Sender"))
    recipient = _decode_header_val(msg.get("To", "Unknown Recipient"))
    reply_to = msg.get("Reply-To")
    return_path = msg.get("Return-Path")
    message_id = msg.get("Message-ID", f"<{uuid.uuid4()}@anvesh.local>")

    # 3. Authentication Headers
    auth_results = msg.get("Authentication-Results", "")
    spf_header = msg.get("Received-SPF", "")

    spf_status = "NOT OBSERVED"
    if "spf=pass" in auth_results.lower() or "pass" in spf_header.lower():
        spf_status = "PASS"
    elif "spf=fail" in auth_results.lower() or "fail" in spf_header.lower():
        spf_status = "FAIL"
    elif "softfail" in auth_results.lower():
        spf_status = "SOFTFAIL"
    elif "neutral" in auth_results.lower():
        spf_status = "NEUTRAL"

    dkim_status = "NOT OBSERVED"
    if "dkim=pass" in auth_results.lower():
        dkim_status = "PASS"
    elif "dkim=fail" in auth_results.lower():
        dkim_status = "FAIL"
    elif "neutral" in auth_results.lower() and "dkim" in auth_results.lower():
        dkim_status = "NEUTRAL"

    dmarc_status = "NOT OBSERVED"
    if "dmarc=pass" in auth_results.lower():
        dmarc_status = "PASS"
    elif "dmarc=fail" in auth_results.lower():
        dmarc_status = "FAIL"

    # 4. Received Hop Traversal & Multi-Hop GeoIP Resolution
    received_headers = msg.get_all("Received") or []
    hops = []
    observable_public_ips = []
    all_hop_ips = []

    raw_hops_data = []
    for idx, r_header in enumerate(received_headers):
        ips = extract_ips_from_text(r_header)
        for ip in ips:
            if is_public_ip(ip) and ip not in observable_public_ips:
                observable_public_ips.append(ip)
            if ip not in all_hop_ips:
                all_hop_ips.append(ip)
        raw_hops_data.append({
            "hop": idx + 1,
            "raw": r_header[:350].strip(),
            "ips": ips
        })

    # Earliest observable public IP (origin candidate)
    probable_origin_ip = observable_public_ips[-1] if observable_public_ips else None

    # Batch GeoIP resolution across all discovered public and private IPs (ip-api.com live integration)
    geo_map = ip_enrichment_service.batch_query_geoip(all_hop_ips)

    # Build fully enriched relay hop chain with real coordinates, city, region, country, and ISP
    for hop_item in raw_hops_data:
        h_ips = hop_item["ips"]
        primary_ip = None
        for ip in h_ips:
            if is_public_ip(ip):
                primary_ip = ip
                break
        if not primary_ip and h_ips:
            primary_ip = h_ips[0]

        geo = geo_map.get(primary_ip, {}) if primary_ip else {}
        is_pub = is_public_ip(primary_ip) if primary_ip else False
        is_orig = (primary_ip == probable_origin_ip) if (primary_ip and probable_origin_ip) else False

        hops.append({
            "hop": hop_item["hop"],
            "raw": hop_item["raw"],
            "ips": h_ips,
            "ip": primary_ip,
            "is_public": is_pub,
            "is_origin": is_orig,
            "latitude": geo.get("latitude"),
            "longitude": geo.get("longitude"),
            "lat": geo.get("latitude"),
            "lon": geo.get("longitude"),
            "city": geo.get("city") or ("Internal Subnet" if not is_pub and primary_ip else None),
            "region": geo.get("region") or geo.get("regionName") or ("RFC-1918" if not is_pub and primary_ip else None),
            "country": geo.get("country") or ("Private Network" if not is_pub and primary_ip else "Unknown Location"),
            "country_code": geo.get("country_code") or ("PRV" if not is_pub and primary_ip else None),
            "isp": geo.get("isp") or ("Local Private Network" if not is_pub and primary_ip else "Upstream Transit Network"),
            "asn": geo.get("asn"),
            "timezone": geo.get("timezone")
        })

    # Earliest observable public IP Authoritative Enrichment
    ip_intel = {}
    if probable_origin_ip:
        ip_intel = intelligence_service.lookup_ip(probable_origin_ip)

    # Origin Confidence Assessment (RFC & Infrastructure-Aware)
    auth_matrix = {"spf": spf_status, "dkim": dkim_status, "dmarc": dmarc_status}
    origin_eval = attribution_service.evaluate_origin_confidence(
        probable_origin_ip=probable_origin_ip,
        hops=hops,
        cloud_classification=ip_intel.get("cloud_classification"),
        is_private=not bool(observable_public_ips),
        auth_status=auth_matrix
    )
    origin_confidence = origin_eval["level"]

    # Strictly IP-associated infrastructure location (Never 'Attacker Location')
    country_name = ip_intel.get("country") if ip_intel else None
    approximate_location = (
        f"IP-associated location: {country_name}" if country_name and country_name != "External Public Route (Unenriched)"
        else (f"Observed Public Gateway [{probable_origin_ip}]" if probable_origin_ip else "Internal/Private Network Only")
    )

    # 5. Extract Observables (Domains, URLs, IPs, Hashes)
    extracted_observables = []
    
    # Add SHA-256
    extracted_observables.append({
        "type": "HASH",
        "value": sha256_hash,
        "description": "SHA-256 evidence fingerprint of raw email"
    })
    
    # Add IPs
    for ip in observable_public_ips:
        extracted_observables.append({
            "type": "IP",
            "value": ip,
            "description": "Public relay IP extracted from Received headers"
        })
        
    # Add Domains
    domains = extract_domains_from_text(f"{sender} {recipient} {reply_to or ''} {return_path or ''}")
    for d in domains:
        extracted_observables.append({
            "type": "DOMAIN",
            "value": d,
            "description": "Domain associated with sender/recipient"
        })

    # Add URLs
    urls = extract_urls_from_text(raw_text)
    for u in urls:
        extracted_observables.append({
            "type": "URL",
            "value": u[:200],
            "description": "URL extracted from email body"
        })

    # 6. Risk Assessment (Explainable scoring)
    reasons = []
    auth_score = 0
    behavior_score = 0
    infra_score = 0

    if spf_status == "FAIL":
        auth_score += 15
        reasons.append("SPF validation failure for sender identity")
    if dkim_status == "FAIL":
        auth_score += 10
        reasons.append("DKIM cryptographic signature verification failure")
    if dmarc_status == "FAIL":
        auth_score += 10
        reasons.append("DMARC policy check failed")

    if reply_to and sender and reply_to.lower().strip() != sender.lower().strip():
        behavior_score += 10
        reasons.append(f"Reply-To mismatch (Claims: {sender} -> Replies to: {reply_to})")

    content_lower = raw_text.lower()
    bec_keywords = ["wire transfer", "urgent payment", "bank account", "gift card", "payroll", "swift", "confidential m&a", "invoice overdue"]
    for kw in bec_keywords:
        if kw in content_lower:
            behavior_score += 10
            reasons.append(f"BEC financial pressure keyword observed: '{kw}'")
            break

    # Financial Promotional / Investment Lure Keywords (Spam & Fraud Lures)
    promo_keywords = ["nfo", "investment opportunity", "new fund offer", "pre-approved", "mutual fund", "credit card approved", "guaranteed returns", "exclusive offer", "worth exploring"]
    for pkw in promo_keywords:
        if pkw in content_lower:
            behavior_score += 15
            reasons.append(f"Unsolicited financial promotional lure keyword observed: '{pkw}'")
            break

    # Opaque Click-Tracking Redirect Links (Phishing & Evasion Indicator)
    for u in urls:
        if re.search(r"/(?:r|track|click|redirect|goto|lnk)/\?|\b(?:id=|p1=|token=|track=)", u) or "%40" in u:
            behavior_score += 15
            reasons.append(f"Opaque click-tracking redirect link detected: '{u[:65]}...'")
            break

    # Bulk Mailer & Unsolicited Marketing Headers
    if msg.get("List-Unsubscribe") or "bulk" in (msg.get("Precedence") or "").lower():
        behavior_score += 15
        reasons.append("Unsolicited bulk marketing campaign headers detected (List-Unsubscribe observed)")

    # Institutional Brand Name Divergence on Multi-Tier Mailer
    if '"' in sender or "<" in sender:
        d_name = sender.split("<")[0].strip(' "\'')
        a_part = sender.split("<")[-1].strip(' >') if "<" in sender else sender
        if any(b in d_name.lower() for b in ["bank", "hdfc", "sbi", "icici", "axis", "chase", "paypal", "microsoft"]):
            s_dom = a_part.split("@")[-1].lower() if "@" in a_part else ""
            if "mailers." in s_dom or "promo" in s_dom or s_dom.count(".") >= 3:
                behavior_score += 20
                reasons.append(f"Institutional brand name '{d_name}' routed through multi-tier bulk mailer ('{s_dom}')")

    if origin_confidence in ("HIGH", "MEDIUM") and probable_origin_ip:
        infra_score += 10

    # Evaluate infrastructure indicators (TOR, VPN, abuse score)
    if probable_origin_ip and ip_intel:
        extra_infra, extra_reasons = risk_engine.evaluate_infrastructure_risk(
            vpn_tor_proxy_indicator=ip_intel.get("vpn_tor_proxy_indicator", "NONE"),
            abuse_score=ip_intel.get("reputation_score")
        )
        infra_score += extra_infra
        for r in extra_reasons:
            if r not in reasons:
                reasons.append(r)

    # ML Semantic Vector & NLP Classification
    ml_res = ml_classifier.classify(text=raw_text, sender=sender, subject=subject)
    ml_score = ml_res["ml_score"]
    for factor in ml_res["ml_factors"]:
        if factor not in reasons:
            reasons.append(factor)

    # Model 3B: Lookalike Domain & Brand Impersonation Analysis
    sender_domain = ""
    if "@" in sender:
        sender_domain = sender.split("@")[-1].strip(" >\t\r\n").lower()
    
    lookalike_evidence = lookalike_service.detect_lookalike(sender_domain) if sender_domain else {
        "model": "lookalike_domain_v1",
        "signal": "NONE",
        "raw_model_score": 0.0,
        "deterministic_indicators": [],
        "candidate_domain": "",
        "trusted_domain": "",
        "features": {},
        "explanation": ["No sender domain extracted."],
        "model_status": "FROZEN",
        "disclaimer": "Domain similarity evidence indicates possible impersonation infrastructure. This does not establish attacker identity."
    }

    lookalike_score, lookalike_reasons = risk_engine.evaluate_lookalike_risk(lookalike_evidence)
    for lr in lookalike_reasons:
        if lr not in reasons:
            reasons.append(lr)

    if lookalike_evidence.get("signal") in ("HIGH", "MEDIUM") and sender_domain:
        extracted_observables.append({
            "type": "DOMAIN",
            "value": sender_domain,
            "description": f"Model 3B: Lookalike domain candidate impersonating '{lookalike_evidence.get('trusted_domain')}' ({lookalike_evidence.get('signal')} signal)"
        })

    # Model 3A: Identity & Header Impersonation Analysis
    auth_ctx = {
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status
    }
    identity_evidence = identity_impersonation_service.evaluate(
        sender_header=sender,
        reply_to_header=reply_to,
        model3b_result=lookalike_evidence,
        auth_context=auth_ctx
    )
    identity_score, identity_reasons = risk_engine.evaluate_identity_risk(identity_evidence)
    for ir in identity_reasons:
        if ir not in reasons:
            reasons.append(ir)

    if identity_evidence.get("identity_impersonation_detected"):
        extracted_observables.append({
            "type": "IDENTITY_IMPERSONATION",
            "value": f"{identity_evidence.get('observed_identity')} <{identity_evidence.get('observed_sender')}>",
            "description": f"Model 3A: Identity impersonation signal ({identity_evidence.get('confidence')}, score {identity_evidence.get('identity_impersonation_score')}/100)"
        })

    # Disposable & Temporary Email Intelligence (Phase 12.5)
    disposable_intel = disposable_email_service.classify_sender(sender).model_dump()
    disposable_score, disposable_reasons = risk_engine.evaluate_disposable_email_risk(disposable_intel)
    for dr in disposable_reasons:
        if dr not in reasons:
            reasons.append(dr)

    if disposable_intel.get("classification") == "DISPOSABLE" or disposable_intel.get("is_disposable"):
        prov_name = disposable_intel.get("provider_name")
        prov_str = f" ({prov_name})" if prov_name else ""
        extracted_observables.append({
            "type": "INTELLIGENCE_OBSERVATION",
            "value": disposable_intel.get("domain"),
            "description": f"Disposable Email Intelligence: Known disposable provider{prov_str}"
        })

    risk_result = risk_engine.calculate_risk(
        ml_score=ml_score,
        auth_risk=auth_score,
        infra_risk=infra_score,
        behavior_bec_risk=behavior_score,
        lookalike_risk=lookalike_score,
        identity_risk=identity_score,
        reasons=reasons,
        disposable_risk=disposable_score
    )

    case_num = f"ANV-2026-{uuid.uuid4().hex[:6].upper()}"
    evidence_id = f"EVD-{uuid.uuid4().hex[:8].upper()}"
    created_at = datetime.utcnow().isoformat()

    # 7. Persist Case to Supabase
    case_row = {
        "case_number": case_num,
        "title": f"Investigation of: {subject[:80]}",
        "description": f"Forensic analysis of message from '{sender}'. Risk score {risk_result['risk_score']}/100.",
        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],
        "threat_type": "BEC" if behavior_score >= 10 else ("SPOOFING_IMPERSONATION" if auth_score > 0 else "SPAM_BENIGN"),
        "status": "UNDER_REVIEW" if risk_result["risk_score"] >= 40 else "NEW",
        "probable_origin_ip": probable_origin_ip,
        "origin_confidence": origin_confidence,
        "approximate_location": approximate_location,
        "created_at": created_at
    }
    created_case = supabase.insert("cases", case_row)
    case_db_id = created_case.get("id") if created_case else str(uuid.uuid4())

    # Persist Email
    email_row = {
        "case_id": case_db_id,
        "message_id": message_id,
        "subject": subject,
        "sender": sender,
        "reply_to": reply_to,
        "return_path": return_path,
        "recipient": recipient,
        "body_hash_sha256": sha256_hash,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "relay_count": len(hops),
        "observed_relays_json": hops,
        "raw_headers": raw_text[:6000]
    }
    supabase.insert("emails", email_row)

    # Persist Evidence
    evidence_row = {
        "evidence_id": evidence_id,
        "case_id": case_db_id,
        "file_name": file_name,
        "file_size_bytes": file_size,
        "sha256_hash": sha256_hash,
        "uploaded_by": "SOC_ANALYST"
    }
    supabase.insert("evidence", evidence_row)

    # Persist Observables into IOCs table in a single batch call
    ioc_rows = [
        {
            "case_id": case_db_id,
            "ioc_type": obs["type"],
            "value": obs["value"],
            "description": obs["description"],
            "reputation_score": 80 if obs["type"] == "IP" and probable_origin_ip == obs["value"] and risk_result["risk_score"] >= 70 else 0
        }
        for obs in extracted_observables
    ]
    if ioc_rows:
        supabase.insert_batch("iocs", ioc_rows)

    # Persist Infrastructure Intelligence
    if probable_origin_ip and ip_intel:
        infra_row = {
            "case_id": case_db_id,
            "ip_address": probable_origin_ip,
            "ip_version": ip_intel.get("ip_version", 4),
            "is_private": ip_intel.get("classification") == "RFC1918_PRIVATE_ADDRESS",
            "country": ip_intel.get("country"),
            "region": ip_intel.get("region"),
            "city": ip_intel.get("city"),
            "latitude": ip_intel.get("latitude"),
            "longitude": ip_intel.get("longitude"),
            "asn": ip_intel.get("asn"),
            "isp": ip_intel.get("isp"),
            "organization": ip_intel.get("organization"),
            "hosting_provider": ip_intel.get("hosting_provider"),
            "cloud_classification": ip_intel.get("cloud_classification"),
            "classification_source": ip_intel.get("classification_source"),
            "vpn_tor_proxy_indicator": ip_intel.get("vpn_tor_proxy_indicator", "NONE"),
            "reputation": str(ip_intel.get("reputation_score") or "UNKNOWN"),
            "status": ip_intel.get("status", "OBSERVED"),
            "provider": "AUTHORITATIVE_BGP_AND_REGISTRY",
            "lookup_timestamp": ip_intel.get("lookup_timestamp", created_at)
        }
        supabase.insert("infrastructure_intelligence", infra_row)

    # Persist Attribution Assessment (Actor Identity: strictly NOT ESTABLISHED)
    attribution = attribution_service.generate_attribution_assessment(
        case_title=case_row["title"],
        risk_level=risk_result["risk_level"],
        risk_score=risk_result["risk_score"],
        origin_confidence=origin_confidence,
        cloud_classification=ip_intel.get("cloud_classification"),
        probable_origin_ip=probable_origin_ip,
        asn=ip_intel.get("asn"),
        threat_type=case_row["threat_type"]
    )
    attr_row = {
        "case_id": case_db_id,
        "threat_risk": attribution["threat_risk"],
        "observed_infrastructure": attribution["observed_infrastructure"],
        "origin_confidence": attribution["origin_confidence"],
        "actor_identity": attribution["actor_identity"],
        "attribution_boundary": attribution["attribution_boundary"],
        "reason": attribution["reason"],
        "created_at": created_at
    }
    supabase.insert("attribution_assessments", attr_row)

    # Persist Evidence Gaps
    is_cloud = ip_intel.get("cloud_classification") in (
        "MICROSOFT_365_OR_AZURE", "GOOGLE_WORKSPACE_OR_GCP", "AMAZON_WEB_SERVICES"
    )
    auth_pass = spf_status == "PASS" and dkim_status == "PASS"
    gaps = attribution_service.generate_evidence_gaps(
        threat_type=case_row["threat_type"],
        is_cloud_provider=is_cloud,
        origin_confidence=origin_confidence,
        auth_pass=auth_pass
    )
    gap_row = {
        "case_id": case_db_id,
        "current_evidence": gaps["current_evidence"],
        "identified_gaps": gaps["identified_gaps"],
        "additional_evidence_options": gaps["additional_evidence_options"],
        "recommended_next_action": gaps["recommended_next_action"],
        "created_at": created_at
    }
    supabase.insert("evidence_gaps", gap_row)

    # If High/Critical Risk, Create Alert
    if risk_result["risk_score"] >= 70:
        alert_row = {
            "case_id": case_db_id,
            "title": f"High Risk: {subject[:60]}",
            "summary": "; ".join(reasons[:2]) if reasons else "High-risk forensic indicators detected.",
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "threat_type": case_row["threat_type"],
            "is_reviewed": False,
            "created_at": created_at
        }
        supabase.insert("alerts", alert_row)

    # 8. Deterministic Campaign Intelligence Correlation
    case_row_with_id = {**case_row, "id": case_db_id}
    campaign_res = campaign_service.correlate_and_assign_case(
        case_data=case_row_with_id,
        email_data=email_row,
        observables=extracted_observables,
        infra_data=ip_intel,
        lookalike_evidence=lookalike_evidence
    )

    timeline = [
        {
            "step": 1,
            "timestamp": created_at,
            "title": "Email Ingested & SHA-256 Registered",
            "description": f"Raw message payload received ({file_size} bytes). Cryptographic evidence fingerprint: {sha256_hash}.",
            "source": "FORENSIC_INGESTION_ENGINE"
        },
        {
            "step": 2,
            "timestamp": created_at,
            "title": "RFC-822 Headers Parsed",
            "description": f"Extracted From: {sender}, Subject: {subject}.",
            "source": "RFC822_PARSER"
        },
        {
            "step": 3,
            "timestamp": created_at,
            "title": "Cryptographic Authentication Evaluated",
            "description": f"SPF: {spf_status}, DKIM: {dkim_status}, DMARC: {dmarc_status}.",
            "source": "AUTH_VERIFIER"
        },
        {
            "step": 4,
            "timestamp": created_at,
            "title": "SMTP Hop Traversal Completed",
            "description": f"Reconstructed {len(hops)} relay hops. Probable Origin IP: {probable_origin_ip or 'Not established'}.",
            "source": "ROUTE_TRACER"
        },
        {
            "step": 5,
            "timestamp": created_at,
            "title": "Deterministic Risk Scoring & Attribution",
            "description": f"Assessed normalized risk score {risk_result['risk_score']}/100 ({risk_result['risk_level']}). Attribution boundary registered.",
            "source": "ANVESH_RISK_ENGINE"
        }
    ]

    if campaign_res and campaign_res.get("campaign"):
        cmp_meta = campaign_res["campaign"]
        timeline.append({
            "step": 6,
            "timestamp": created_at,
            "title": f"Campaign Correlation ({cmp_meta.get('confidence')} Confidence)",
            "description": f"Associated with Potential Campaign {cmp_meta.get('campaign_id')} based on observable evidence overlap.",
            "source": "CAMPAIGN_CORRELATION_ENGINE"
        })

    # 9. Cross-Modal Forensic Signal Fusion (Phase 9B)
    fusion_result = forensic_fusion_service.fuse(
        ml_signal=ml_res,
        behavior_signal={"behavior_score": behavior_score, "bec_keywords": [kw for kw in bec_keywords if kw in content_lower]},
        identity_impersonation=identity_evidence,
        lookalike_evidence=lookalike_evidence,
        auth_context={"spf": spf_status, "dkim": dkim_status, "dmarc": dmarc_status},
        transport_evidence={"origin_confidence": origin_confidence, "relay_count": len(hops)},
        threat_intel=ip_intel,
        campaign=campaign_res.get("campaign") if campaign_res else None,
        evidence_gaps=gaps,
        disposable_evidence=disposable_intel
    )

    return {
        "case_number": case_num,
        "id": case_db_id,
        "title": case_row["title"],
        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],
        "threat_type": case_row["threat_type"],
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "probable_origin_ip": probable_origin_ip,
        "origin_confidence": origin_confidence,
        "approximate_location": approximate_location,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "category_scores": risk_result.get("category_scores"),
        "ml_signal": ml_res,
        "lookalike_evidence": lookalike_evidence,
        "identity_impersonation": identity_evidence,
        "email_provider_intelligence": disposable_intel,
        "flagged_reasons": reasons,
        "hops": hops,
        "observables": extracted_observables,
        "timeline": timeline,
        "infrastructure": ip_intel,
        "attribution": attribution,
        "evidence_gaps": gaps,
        "evidence_id": evidence_id,
        "sha256_hash": sha256_hash,
        "created_at": created_at,
        "campaign": campaign_res.get("campaign") if campaign_res else None,
        "campaign_correlation": campaign_res.get("correlation") if campaign_res else None,
        "fusion": fusion_result,
        "is_simulated_data": False
    }
