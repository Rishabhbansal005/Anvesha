"""
ANVESH Campaign Intelligence Foundation Service.
Deterministic, Explainable Evidence Correlation & Campaign Clustering.
Strict Zero-Fabrication and Non-Attribution Enforcement.
"""
import re
import uuid
import ipaddress
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Set
from app.database.supabase_client import supabase


# ---------------------------------------------------------------------------
# Strict False-Positive Protection Exclusions
# ---------------------------------------------------------------------------
EXCLUDED_FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "yahoo.co.uk",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me", "pm.me",
    "aol.com", "zoho.com", "yandex.com", "mail.com", "gmx.com"
}

EXCLUDED_CLOUD_PROVIDERS = {
    "MICROSOFT_365_OR_AZURE",
    "GOOGLE_WORKSPACE_OR_GCP",
    "AMAZON_WEB_SERVICES",
    "CLOUDFLARE",
    "FASTLY",
    "AKAMAI"
}

EXCLUDED_PUBLIC_RESOLVERS = {
    "8.8.8.8", "8.8.4.4",
    "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220"
}

COMMON_SUBJECT_PREFIXES = [
    r"^re:\s*", r"^fw:\s*", r"^fwd:\s*", r"^aw:\s*", r"^sv:\s*",
    r"^\[external\]\s*", r"^urgent:\s*", r"^action required:\s*"
]

FINANCIAL_BEC_PHRASES = [
    "wire transfer", "urgent payment", "bank account", "gift card",
    "payroll update", "direct deposit", "confidential invoice",
    "swift transfer", "vendor settlement", "ach payment"
]


# ---------------------------------------------------------------------------
# Normalization Pipeline
# ---------------------------------------------------------------------------
def normalize_email(email_str: Optional[str]) -> Dict[str, str]:
    """
    Normalizes email address:
    - Strips surrounding brackets, quotes, display names.
    - Lowers domain portion while safely preserving local part representation.
    - Preserves original.
    """
    if not email_str:
        return {"original": "", "normalized": "", "domain": "", "local_part": ""}
    
    orig = email_str
    match = re.search(r'<([^>]+)>', orig)
    addr = match.group(1).strip() if match else orig

    if "@" in addr:
        parts = addr.split("@", 1)
        local_part = parts[0].strip()
        domain_part = parts[1].strip().lower().rstrip(".")
        normalized = f"{local_part}@{domain_part}"
    else:
        local_part = addr
        domain_part = ""
        normalized = addr.lower()

    return {
        "original": orig,
        "normalized": normalized,
        "domain": domain_part,
        "local_part": local_part
    }


def normalize_domain(domain_str: Optional[str]) -> Dict[str, str]:
    """
    Normalizes domain string:
    - Lowercase, strip whitespace and trailing dot.
    - Safely handles IDNA/punycode decoding.
    - Preserves original.
    """
    if not domain_str:
        return {"original": "", "normalized": "", "is_punycode": False}
    
    orig = domain_str
    clean = orig.strip().lower().rstrip(".")
    is_punycode = "xn--" in clean
    try:
        decoded = clean.encode("idna").decode("ascii") if is_punycode else clean
    except Exception:
        decoded = clean

    return {
        "original": orig,
        "normalized": decoded,
        "is_punycode": is_punycode
    }


def normalize_url(url_str: Optional[str]) -> Dict[str, str]:
    """
    Normalizes URL string:
    - Lowercase scheme and hostname.
    - Extracts host domain independently.
    - Preserves path and original.
    """
    if not url_str:
        return {"original": "", "normalized": "", "hostname": "", "domain": ""}

    orig = url_str
    target = orig.strip()
    if "://" not in target:
        target = f"http://{target}"
    try:
        parsed = urllib.parse.urlparse(target)
        host = (parsed.hostname or "").lower().rstrip(".")
        path = parsed.path or "/"
        normalized = f"{parsed.scheme.lower()}://{host}{path}"
        domain = host
        if domain.startswith("www."):
            domain = domain[4:]
    except Exception:
        host = target.lower()
        domain = host
        normalized = target

    return {
        "original": orig,
        "normalized": normalized,
        "hostname": host,
        "domain": domain
    }


def normalize_ip(ip_str: Optional[str]) -> Dict[str, Any]:
    """
    Normalizes IP address:
    - Canonical representation for IPv4 and IPv6.
    - Detects private/loopback/cloud resolver.
    - Preserves original.
    """
    if not ip_str:
        return {"original": "", "normalized": "", "is_valid": False, "is_private": False, "version": None}

    orig = ip_str
    try:
        ip_obj = ipaddress.ip_address(orig.strip())
        return {
            "original": orig,
            "normalized": str(ip_obj),
            "is_valid": True,
            "is_private": ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved,
            "version": ip_obj.version
        }
    except ValueError:
        return {
            "original": orig,
            "normalized": orig.strip(),
            "is_valid": False,
            "is_private": False,
            "version": None
        }


def normalize_subject(subject_str: Optional[str]) -> Dict[str, str]:
    """
    Normalizes email subject:
    - Iteratively strips common reply/forward prefixes (RE:, FW:, FWD:, etc.).
    - Normalizes whitespace and converts to lowercase for token/similarity comparison.
    - Preserves original.
    """
    if not subject_str:
        return {"original": "", "normalized": "", "cleaned": ""}

    orig = subject_str
    cleaned = orig.strip()
    changed = True
    while changed:
        changed = False
        for prefix in COMMON_SUBJECT_PREFIXES:
            new_sub = re.sub(prefix, "", cleaned, flags=re.IGNORECASE).strip()
            if new_sub != cleaned:
                cleaned = new_sub
                changed = True

    # Collapse multiple whitespace
    normalized = re.sub(r'\s+', ' ', cleaned).strip().lower()
    return {
        "original": orig,
        "normalized": normalized,
        "cleaned": cleaned
    }


def calculate_lexical_similarity(str1: str, str2: str) -> float:
    """Calculates deterministic token Jaccard similarity between two normalized strings."""
    if not str1 or not str2:
        return 0.0
    tokens1 = set(str1.split())
    tokens2 = set(str2.split())
    if not tokens1 or not tokens2:
        return 0.0
    intersection = len(tokens1.intersection(tokens2))
    union = len(tokens1.union(tokens2))
    return intersection / float(union) if union > 0 else 0.0


# ---------------------------------------------------------------------------
# Deterministic Correlation Engine
# ---------------------------------------------------------------------------
class CampaignCorrelationService:
    """
    Deterministic correlation engine for campaign discovery.
    Evaluates observable evidence signals with explainable weights and false-positive guards.
    """

    def evaluate_correlation(
        self,
        case_a: Dict[str, Any],
        case_b: Dict[str, Any],
        email_a: Optional[Dict[str, Any]] = None,
        email_b: Optional[Dict[str, Any]] = None,
        observables_a: Optional[List[Dict[str, Any]]] = None,
        observables_b: Optional[List[Dict[str, Any]]] = None,
        infra_a: Optional[Dict[str, Any]] = None,
        infra_b: Optional[Dict[str, Any]] = None,
        lookalike_a: Optional[Dict[str, Any]] = None,
        lookalike_b: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Evaluates deterministic evidence overlap between two cases.
        Returns explainable score (0-100), confidence level, and itemized reasons.
        """
        reasons: List[Dict[str, Any]] = []
        score = 0

        # Normalization of inputs
        email_a = email_a or {}
        email_b = email_b or {}
        observables_a = observables_a or []
        observables_b = observables_b or []
        infra_a = infra_a or {}
        infra_b = infra_b or {}
        lookalike_a = lookalike_a or {}
        lookalike_b = lookalike_b or {}

        # -------------------------------------------------------------------
        # Signal 1: Exact Reply-To Address Overlap (+35 Strong)
        # -------------------------------------------------------------------
        reply_a = normalize_email(email_a.get("reply_to"))
        reply_b = normalize_email(email_b.get("reply_to"))
        if reply_a["normalized"] and reply_b["normalized"]:
            if reply_a["normalized"] == reply_b["normalized"]:
                score += 35
                reasons.append({
                    "signal": "EXACT_REPLY_TO",
                    "strength": "STRONG",
                    "weight": 35,
                    "description": f"Both cases direct replies to the identical address: '{reply_a['normalized']}'."
                })
            elif reply_a["domain"] and reply_a["domain"] == reply_b["domain"] and reply_a["domain"] not in EXCLUDED_FREEMAIL_DOMAINS:
                score += 20
                reasons.append({
                    "signal": "REPLY_TO_DOMAIN_OVERLAP",
                    "strength": "MEDIUM",
                    "weight": 20,
                    "description": f"Both cases utilize distinct Reply-To addresses sharing private domain: '{reply_a['domain']}'."
                })

        # -------------------------------------------------------------------
        # Signal 2: Observable Suspicious Domain Overlap (+35 Strong)
        # -------------------------------------------------------------------
        domains_a = {normalize_domain(o.get("value"))["normalized"] for o in observables_a if o.get("ioc_type") == "DOMAIN" or o.get("type") == "DOMAIN"}
        domains_b = {normalize_domain(o.get("value"))["normalized"] for o in observables_b if o.get("ioc_type") == "DOMAIN" or o.get("type") == "DOMAIN"}
        # Exclude common freemail and cloud domains
        shared_domains = (domains_a & domains_b) - EXCLUDED_FREEMAIL_DOMAINS
        for dom in shared_domains:
            if dom and "." in dom:
                score += 35
                reasons.append({
                    "signal": "EXACT_SUSPICIOUS_DOMAIN",
                    "strength": "STRONG",
                    "weight": 35,
                    "description": f"Observed overlap on suspicious domain observable: '{dom}'."
                })
                break  # Count once for primary domain match

        # -------------------------------------------------------------------
        # Signal 3: Exact Suspicious IOC / URL Overlap (+30 Strong)
        # -------------------------------------------------------------------
        urls_a = {normalize_url(o.get("value"))["normalized"] for o in observables_a if o.get("ioc_type") == "URL" or o.get("type") == "URL"}
        urls_b = {normalize_url(o.get("value"))["normalized"] for o in observables_b if o.get("ioc_type") == "URL" or o.get("type") == "URL"}
        shared_urls = urls_a & urls_b
        for u in shared_urls:
            score += 30
            reasons.append({
                "signal": "EXACT_IOC_OVERLAP",
                "strength": "STRONG",
                "weight": 30,
                "description": f"Identical URL observable present in both cases: '{u[:60]}...'."
            })
            break

        # -------------------------------------------------------------------
        # Signal 4: Public Origin IP Overlap with Cloud/Resolver Guard (+25 Strong)
        # -------------------------------------------------------------------
        ip_a = normalize_ip(case_a.get("probable_origin_ip"))
        ip_b = normalize_ip(case_b.get("probable_origin_ip"))
        if ip_a["is_valid"] and ip_b["is_valid"] and ip_a["normalized"] == ip_b["normalized"]:
            # Check false positive guards: private network, public resolver, or cloud provider
            cloud_a = infra_a.get("cloud_classification", "")
            cloud_b = infra_b.get("cloud_classification", "")
            is_cloud = (cloud_a in EXCLUDED_CLOUD_PROVIDERS) or (cloud_b in EXCLUDED_CLOUD_PROVIDERS)
            is_resolver = ip_a["normalized"] in EXCLUDED_PUBLIC_RESOLVERS

            if not ip_a["is_private"] and not is_resolver and not is_cloud:
                score += 25
                reasons.append({
                    "signal": "EXACT_PUBLIC_IP",
                    "strength": "STRONG",
                    "weight": 25,
                    "description": f"Matching originating public network IP observed: {ip_a['normalized']}."
                })
            else:
                reasons.append({
                    "signal": "SHARED_PUBLIC_GATEWAY_GUARD",
                    "strength": "WEAK",
                    "weight": 0,
                    "description": f"Origin IP {ip_a['normalized']} belongs to shared cloud/resolver infrastructure ({cloud_a or 'Public Gateway'}). Weight suppressed per false-positive protection invariant."
                })

        # -------------------------------------------------------------------
        # Signal 5: Same Lookalike Brand Target (Model 3B) (+25 Strong)
        # -------------------------------------------------------------------
        target_a = lookalike_a.get("trusted_domain") or lookalike_a.get("target_brand")
        target_b = lookalike_b.get("trusted_domain") or lookalike_b.get("target_brand")
        if target_a and target_b and target_a.lower() == target_b.lower() and lookalike_a.get("signal") in ("HIGH", "MEDIUM") and lookalike_b.get("signal") in ("HIGH", "MEDIUM"):
            score += 25
            reasons.append({
                "signal": "SAME_LOOKALIKE_TARGET",
                "strength": "STRONG",
                "weight": 25,
                "description": f"Model 3B evidence identifies shared brand impersonation target: '{target_a}'."
            })

        # -------------------------------------------------------------------
        # Signal 6: Exact Sender Address (+20 Medium)
        # -------------------------------------------------------------------
        sender_a = normalize_email(email_a.get("sender"))
        sender_b = normalize_email(email_b.get("sender"))
        if sender_a["normalized"] and sender_b["normalized"]:
            if sender_a["normalized"] == sender_b["normalized"]:
                score += 20
                reasons.append({
                    "signal": "EXACT_SENDER",
                    "strength": "MEDIUM",
                    "weight": 20,
                    "description": f"Both cases originate from identical sender address: '{sender_a['normalized']}'."
                })
            elif sender_a["domain"] and sender_a["domain"] == sender_b["domain"] and sender_a["domain"] not in EXCLUDED_FREEMAIL_DOMAINS:
                score += 15
                reasons.append({
                    "signal": "SENDER_DOMAIN_OVERLAP",
                    "strength": "MEDIUM",
                    "weight": 15,
                    "description": f"Different local sender accounts sharing registered domain: '{sender_a['domain']}'."
                })

        # -------------------------------------------------------------------
        # Signal 7: Exact Message-ID Domain (+15 Medium)
        # -------------------------------------------------------------------
        msg_id_a = email_a.get("message_id", "")
        msg_id_b = email_b.get("message_id", "")
        domain_msg_a = msg_id_a.split("@")[-1].rstrip(">").strip().lower() if "@" in msg_id_a else ""
        domain_msg_b = msg_id_b.split("@")[-1].rstrip(">").strip().lower() if "@" in msg_id_b else ""
        if domain_msg_a and domain_msg_b and domain_msg_a == domain_msg_b and domain_msg_a not in EXCLUDED_FREEMAIL_DOMAINS:
            score += 15
            reasons.append({
                "signal": "EXACT_MSG_ID_DOMAIN",
                "strength": "MEDIUM",
                "weight": 15,
                "description": f"Shared originating mail server Message-ID domain infrastructure: '{domain_msg_a}'."
            })

        # -------------------------------------------------------------------
        # Signal 8: Normalized Subject Similarity (+15 Medium)
        # -------------------------------------------------------------------
        sub_a = normalize_subject(email_a.get("subject") or case_a.get("title"))
        sub_b = normalize_subject(email_b.get("subject") or case_b.get("title"))
        if sub_a["normalized"] and sub_b["normalized"]:
            if sub_a["normalized"] == sub_b["normalized"]:
                score += 15
                reasons.append({
                    "signal": "EXACT_NORMALIZED_SUBJECT",
                    "strength": "MEDIUM",
                    "weight": 15,
                    "description": f"Identical normalized subject line pattern: '{sub_a['cleaned']}'."
                })
            else:
                sim = calculate_lexical_similarity(sub_a["normalized"], sub_b["normalized"])
                if sim >= 0.75:
                    score += 12
                    reasons.append({
                        "signal": "SUBJECT_LEXICAL_SIMILARITY",
                        "strength": "MEDIUM",
                        "weight": 12,
                        "description": f"High lexical similarity ({int(sim*100)}%) between normalized subject lines."
                    })

        # -------------------------------------------------------------------
        # Signal 9: Common Financial / BEC Phrasing (+10 Weak-Med)
        # -------------------------------------------------------------------
        text_a = (email_a.get("raw_headers", "") + " " + (case_a.get("description") or "")).lower()
        text_b = (email_b.get("raw_headers", "") + " " + (case_b.get("description") or "")).lower()
        common_phrases = [p for p in FINANCIAL_BEC_PHRASES if p in text_a and p in text_b]
        if common_phrases:
            score += 10
            reasons.append({
                "signal": "COMMON_FINANCIAL_PHRASE",
                "strength": "WEAK",
                "weight": 10,
                "description": f"Common financial coercion phraseology observed: '{common_phrases[0]}'."
            })

        # -------------------------------------------------------------------
        # Signal 10: Temporal Proximity (+10 Supporting)
        # -------------------------------------------------------------------
        ts_a = case_a.get("created_at") or email_a.get("created_at")
        ts_b = case_b.get("created_at") or email_b.get("created_at")
        if ts_a and ts_b:
            try:
                dt_a = datetime.fromisoformat(ts_a.replace("Z", "+00:00"))
                dt_b = datetime.fromisoformat(ts_b.replace("Z", "+00:00"))
                days_diff = abs((dt_a - dt_b).total_seconds()) / 86400.0
                if days_diff <= 7.0:
                    score += 10
                    reasons.append({
                        "signal": "TEMPORAL_PROXIMITY_CLOSE",
                        "strength": "SUPPORTING",
                        "weight": 10,
                        "description": f"Events observed within {round(days_diff, 1)} days of each other."
                    })
                elif days_diff <= 14.0:
                    score += 5
                    reasons.append({
                        "signal": "TEMPORAL_PROXIMITY_MODERATE",
                        "strength": "SUPPORTING",
                        "weight": 5,
                        "description": f"Events observed within {round(days_diff, 1)} days of each other."
                    })
            except Exception:
                pass

        # -------------------------------------------------------------------
        # Signal 11: Shared ASN / Provider (Context only, 0 or max +2)
        # -------------------------------------------------------------------
        asn_a = infra_a.get("asn")
        asn_b = infra_b.get("asn")
        if asn_a and asn_b and asn_a == asn_b:
            reasons.append({
                "signal": "SHARED_ASN_CONTEXT",
                "strength": "WEAK",
                "weight": 2,
                "description": f"Shared autonomous system (ASN {asn_a}) observed. Contextual environmental factor only."
            })
            score += 2

        # Clamp score to 100
        total_score = min(score, 100)

        # Confidence rating determination
        if total_score >= 75:
            confidence = "HIGH"
            related = True
        elif total_score >= 50:
            confidence = "MEDIUM"
            related = True
        else:
            confidence = "LOW"
            related = False

        return {
            "related": related,
            "confidence": confidence,
            "score": total_score,
            "reasons": reasons
        }

    # -----------------------------------------------------------------------
    # Campaign Explanation Generation (Strictly Deterministic & Evidentiary)
    # -----------------------------------------------------------------------
    def generate_campaign_explanation(
        self,
        campaign_name: str,
        case_count: int,
        email_count: int,
        ioc_count: int,
        evidence_summary: Dict[str, Any],
        first_seen: str,
        last_seen: str
    ) -> str:
        """
        Produces a machine-generated deterministic explanation without attacker attribution.
        """
        time_span = "a single day"
        try:
            dt1 = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            dt2 = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            days = max(1, round(abs((dt2 - dt1).total_seconds()) / 86400.0))
            time_span = f"a {days}-day period"
        except Exception:
            pass

        key_signals = []
        if evidence_summary.get("shared_reply_to_count", 0) > 0:
            key_signals.append(f"{evidence_summary['shared_reply_to_count']} matching Reply-To address(es)")
        if evidence_summary.get("shared_domain_count", 0) > 0:
            key_signals.append(f"{evidence_summary['shared_domain_count']} shared suspicious domain(s)")
        if evidence_summary.get("shared_ip_count", 0) > 0:
            key_signals.append(f"{evidence_summary['shared_ip_count']} overlapping origin IP(s)")
        if evidence_summary.get("lookalike_brand"):
            key_signals.append(f"targeted impersonation of '{evidence_summary['lookalike_brand']}'")
        if evidence_summary.get("subject_patterns"):
            key_signals.append("repetitive subject phraseology")

        signals_str = ", ".join(key_signals) if key_signals else "overlapping observable indicators"

        explanation = (
            f"{case_count} analyzed cases ({email_count} emails) are grouped as related activity based on {signals_str} "
            f"observed within {time_span}. "
            f"The available evidence indicates related threat infrastructure and behavior. "
            f"Actor identity is not established; this grouping represents observable infrastructure correlation."
        )
        return explanation

    # -----------------------------------------------------------------------
    # Campaign Assignment & Ingestion Hook
    # -----------------------------------------------------------------------
    def correlate_and_assign_case(
        self,
        case_data: Dict[str, Any],
        email_data: Optional[Dict[str, Any]] = None,
        observables: Optional[List[Dict[str, Any]]] = None,
        infra_data: Optional[Dict[str, Any]] = None,
        lookalike_evidence: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Checks existing campaigns and cases to identify if the current case belongs to a campaign.
        - Attaches case to existing campaign if correlation score >= 50.
        - Forms a new campaign if two or more cases demonstrate correlation >= 50.
        - Returns campaign metadata or None if ungrouped.
        """
        case_id = case_data.get("id") or case_data.get("case_number")
        if not case_id:
            return None

        # Fetch existing cases
        all_cases = supabase.query("cases", select="*")
        existing_cases = [c for c in all_cases if (c.get("id") != case_id and c.get("case_number") != case_id)]
        if not existing_cases:
            return None

        best_match_case = None
        best_correlation: Optional[Dict[str, Any]] = None
        highest_score = 0

        # Pre-filter candidate cases by observable heuristic signals (same IP, lexical title overlap, or matching threat)
        cur_ip = case_data.get("probable_origin_ip")
        cur_title = (case_data.get("title") or "").lower()
        cur_threat = case_data.get("threat_type")

        candidate_cases = []
        for other_case in existing_cases:
            o_ip = other_case.get("probable_origin_ip")
            o_title = (other_case.get("title") or "").lower()
            o_threat = other_case.get("threat_type")

            # Priority 1: Exact matching probable origin IP
            if cur_ip and o_ip and cur_ip == o_ip:
                candidate_cases.append(other_case)
                continue
            # Priority 2: High lexical subject / title overlap
            if cur_title and o_title and calculate_lexical_similarity(cur_title, o_title) >= 0.35:
                candidate_cases.append(other_case)
                continue
            # Priority 3: Recent cases with same threat type (limit fallback)
            if cur_threat and o_threat and cur_threat == o_threat and len(candidate_cases) < 3:
                candidate_cases.append(other_case)

        # If no heuristic candidate matches, take up to 3 most recent cases
        if not candidate_cases:
            candidate_cases = existing_cases[:3]

        # Evaluate candidate matches against top candidates only (strictly capped at 5)
        for other_case in candidate_cases[:5]:
            o_id = other_case.get("id") or other_case.get("case_number")
            o_emails = supabase.query("emails", select="*", filters={"case_id": f"eq.{o_id}"})
            o_email = o_emails[0] if o_emails else {}
            o_observables = supabase.query("iocs", select="*", filters={"case_id": f"eq.{o_id}"})
            o_infra_list = supabase.query("infrastructure_intelligence", select="*", filters={"case_id": f"eq.{o_id}"})
            o_infra = o_infra_list[0] if o_infra_list else {}

            correlation = self.evaluate_correlation(
                case_a=case_data,
                case_b=other_case,
                email_a=email_data,
                email_b=o_email,
                observables_a=observables,
                observables_b=o_observables,
                infra_a=infra_data,
                infra_b=o_infra,
                lookalike_a=lookalike_evidence,
                lookalike_b={}
            )

            if correlation["related"] and correlation["score"] > highest_score:
                highest_score = correlation["score"]
                best_correlation = correlation
                best_match_case = other_case

        if not best_match_case or not best_correlation or highest_score < 50:
            return None

        now_iso = datetime.utcnow().isoformat()
        campaign_record = None

        # Case 1: Best match case already belongs to a campaign
        matched_campaign_id = best_match_case.get("campaign_id")
        if matched_campaign_id:
            existing_camps = supabase.query("campaigns", select="*", filters={"id": f"eq.{matched_campaign_id}"})
            if existing_camps:
                campaign_record = existing_camps[0]

        # Case 2: No existing campaign, create a new Campaign
        if not campaign_record:
            cmp_num = f"ANV-26-CMP-{uuid.uuid4().hex[:6].upper()}"
            title_lead = (email_data.get("subject") or case_data.get("title") or "Activity Cluster")[:40]
            campaign_record = {
                "id": str(uuid.uuid4()),
                "campaign_id": cmp_num,
                "name": f"Potential Campaign: {title_lead}",
                "status": "ACTIVE",
                "confidence": best_correlation["confidence"],
                "confidence_score": best_correlation["score"],
                "threat_type": case_data.get("threat_type", "BEC"),
                "case_count": 2,
                "email_count": 2,
                "ioc_count": len(observables or []),
                "first_observed_at": best_match_case.get("created_at") or now_iso,
                "last_observed_at": now_iso,
                "created_at": now_iso,
                "updated_at": now_iso,
                "evidence_summary": {
                    "shared_reply_to_count": 1 if any(r["signal"] == "EXACT_REPLY_TO" for r in best_correlation["reasons"]) else 0,
                    "shared_domain_count": 1 if any(r["signal"] == "EXACT_SUSPICIOUS_DOMAIN" for r in best_correlation["reasons"]) else 0,
                    "shared_ip_count": 1 if any(r["signal"] == "EXACT_PUBLIC_IP" for r in best_correlation["reasons"]) else 0,
                    "lookalike_brand": lookalike_evidence.get("trusted_domain") if lookalike_evidence else None,
                    "top_reasons": [r["description"] for r in best_correlation["reasons"][:3]]
                }
            }
            campaign_record["explanation"] = self.generate_campaign_explanation(
                campaign_name=campaign_record["name"],
                case_count=2,
                email_count=2,
                ioc_count=campaign_record["ioc_count"],
                evidence_summary=campaign_record["evidence_summary"],
                first_seen=campaign_record["first_observed_at"],
                last_seen=campaign_record["last_observed_at"]
            )
            created_camp = supabase.insert("campaigns", campaign_record)
            if created_camp:
                campaign_record = created_camp

            # Attach previous case to this new campaign
            other_id = best_match_case.get("id") or best_match_case.get("case_number")
            supabase.update("cases", "id", other_id, {"campaign_id": campaign_record["id"]})
        else:
            # Update existing campaign
            new_count = (campaign_record.get("case_count") or 1) + 1
            new_email_count = (campaign_record.get("email_count") or 1) + 1
            new_ioc_count = (campaign_record.get("ioc_count") or 0) + len(observables or [])
            # Re-evaluate confidence
            avg_score = max(campaign_record.get("confidence_score", 50), best_correlation["score"])
            conf = "HIGH" if avg_score >= 75 else "MEDIUM"
            ev_summary = campaign_record.get("evidence_summary") or {}
            if any(r["signal"] == "EXACT_REPLY_TO" for r in best_correlation["reasons"]):
                ev_summary["shared_reply_to_count"] = (ev_summary.get("shared_reply_to_count") or 0) + 1
            if any(r["signal"] == "EXACT_SUSPICIOUS_DOMAIN" for r in best_correlation["reasons"]):
                ev_summary["shared_domain_count"] = (ev_summary.get("shared_domain_count") or 0) + 1
            if any(r["signal"] == "EXACT_PUBLIC_IP" for r in best_correlation["reasons"]):
                ev_summary["shared_ip_count"] = (ev_summary.get("shared_ip_count") or 0) + 1

            updates = {
                "case_count": new_count,
                "email_count": new_email_count,
                "ioc_count": new_ioc_count,
                "last_observed_at": now_iso,
                "updated_at": now_iso,
                "confidence": conf,
                "confidence_score": avg_score,
                "evidence_summary": ev_summary,
                "explanation": self.generate_campaign_explanation(
                    campaign_name=campaign_record.get("name", "Potential Campaign"),
                    case_count=new_count,
                    email_count=new_email_count,
                    ioc_count=new_ioc_count,
                    evidence_summary=ev_summary,
                    first_seen=campaign_record.get("first_observed_at", now_iso),
                    last_seen=now_iso
                )
            }
            supabase.update("campaigns", "id", campaign_record["id"], updates)
            campaign_record.update(updates)

        # Attach current case to campaign
        supabase.update("cases", "id", case_id, {"campaign_id": campaign_record["id"]})

        # Record timeline event
        timeline_event = {
            "id": str(uuid.uuid4()),
            "campaign_id": campaign_record["id"],
            "case_id": case_id,
            "event_type": "CASE_CORRELATED",
            "timestamp": now_iso,
            "title": f"Case {case_data.get('case_number')} Attached to Campaign",
            "description": f"Correlated with score {best_correlation['score']}/100 ({best_correlation['confidence']}).",
            "signals": best_correlation["reasons"]
        }
        supabase.insert("campaign_timeline", timeline_event)

        return {
            "campaign": campaign_record,
            "correlation": best_correlation,
            "matched_case_number": best_match_case.get("case_number")
        }

    # -----------------------------------------------------------------------
    # Campaign Relationships (Graph Foundation for Phase 8B)
    # -----------------------------------------------------------------------
    def get_campaign_relationships(self, campaign_id: str) -> Dict[str, Any]:
        """
        Builds the relationship nodes and edges for the campaign graph foundation.
        Nodes: CAMPAIGN, CASE, EMAIL, DOMAIN, IP, URL, REPLY_TO, SENDER
        Edges: INCLUDES_CASE, HAS_EMAIL, OBSERVED_DOMAIN, OBSERVED_IP, OBSERVED_URL, OBSERVED_REPLY_TO
        """
        # Resolve campaign
        camps = supabase.query("campaigns", select="*", filters={"id": f"eq.{campaign_id}"})
        if not camps:
            camps = supabase.query("campaigns", select="*", filters={"campaign_id": f"eq.{campaign_id}"})
        if not camps:
            return {"nodes": [], "edges": [], "summary": {}}

        camp = camps[0]
        c_uuid = camp.get("id")

        # Query all related cases
        cases = supabase.query("cases", select="*", filters={"campaign_id": f"eq.{c_uuid}"})
        
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        seen_nodes: Set[str] = set()

        # 1. Root Campaign Node
        camp_node_id = f"camp_{c_uuid}"
        nodes.append({
            "id": camp_node_id,
            "type": "CAMPAIGN",
            "label": camp.get("name") or camp.get("campaign_id"),
            "confidence": camp.get("confidence", "HIGH"),
            "status": camp.get("status", "ACTIVE")
        })
        seen_nodes.add(camp_node_id)

        domains_set = set()
        ips_set = set()
        urls_set = set()
        reply_tos_set = set()
        senders_set = set()

        # 2. Iterate Cases
        for case in cases:
            case_db_id = case.get("id") or case.get("case_number")
            case_node_id = f"case_{case_db_id}"
            if case_node_id not in seen_nodes:
                nodes.append({
                    "id": case_node_id,
                    "type": "CASE",
                    "label": case.get("case_number", "CASE"),
                    "risk_score": case.get("risk_score", 0),
                    "threat_type": case.get("threat_type", "BEC")
                })
                seen_nodes.add(case_node_id)
                edges.append({
                    "source": camp_node_id,
                    "target": case_node_id,
                    "relation": "INCLUDES_CASE",
                    "strength": "STRONG"
                })

            # Fetch case emails
            emails = supabase.query("emails", select="*", filters={"case_id": f"eq.{case_db_id}"})
            for eml in emails:
                eml_id = eml.get("id") or eml.get("message_id")
                eml_node_id = f"eml_{eml_id}"
                if eml_node_id not in seen_nodes:
                    nodes.append({
                        "id": eml_node_id,
                        "type": "EMAIL",
                        "label": eml.get("subject", "Email")[:30],
                        "message_id": eml.get("message_id")
                    })
                    seen_nodes.add(eml_node_id)
                    edges.append({
                        "source": case_node_id,
                        "target": eml_node_id,
                        "relation": "INGESTED_EMAIL",
                        "strength": "STRONG"
                    })

                # Sender
                if eml.get("sender"):
                    norm_sender = normalize_email(eml["sender"])["normalized"]
                    s_node_id = f"sender_{norm_sender}"
                    senders_set.add(norm_sender)
                    if s_node_id not in seen_nodes:
                        nodes.append({"id": s_node_id, "type": "SENDER", "label": norm_sender})
                        seen_nodes.add(s_node_id)
                    edges.append({"source": eml_node_id, "target": s_node_id, "relation": "HAS_SENDER", "strength": "MEDIUM"})

                # Reply-To
                if eml.get("reply_to"):
                    norm_reply = normalize_email(eml["reply_to"])["normalized"]
                    r_node_id = f"reply_{norm_reply}"
                    reply_tos_set.add(norm_reply)
                    if r_node_id not in seen_nodes:
                        nodes.append({"id": r_node_id, "type": "REPLY_TO", "label": norm_reply})
                        seen_nodes.add(r_node_id)
                    edges.append({"source": eml_node_id, "target": r_node_id, "relation": "SPECIFIES_REPLY_TO", "strength": "STRONG"})

            # Fetch case observables
            iocs = supabase.query("iocs", select="*", filters={"case_id": f"eq.{case_db_id}"})
            for ioc in iocs:
                ioc_type = ioc.get("ioc_type") or ioc.get("type")
                val = ioc.get("value", "")
                if ioc_type == "DOMAIN":
                    d_norm = normalize_domain(val)["normalized"]
                    domains_set.add(d_norm)
                    d_node_id = f"dom_{d_norm}"
                    if d_node_id not in seen_nodes:
                        nodes.append({"id": d_node_id, "type": "DOMAIN", "label": d_norm})
                        seen_nodes.add(d_node_id)
                    edges.append({"source": case_node_id, "target": d_node_id, "relation": "OBSERVED_DOMAIN", "strength": "STRONG"})
                elif ioc_type == "IP":
                    ip_norm = normalize_ip(val)["normalized"]
                    ips_set.add(ip_norm)
                    ip_node_id = f"ip_{ip_norm}"
                    if ip_node_id not in seen_nodes:
                        nodes.append({"id": ip_node_id, "type": "IP", "label": ip_norm})
                        seen_nodes.add(ip_node_id)
                    edges.append({"source": case_node_id, "target": ip_node_id, "relation": "OBSERVED_IP", "strength": "STRONG"})
                elif ioc_type == "URL":
                    u_norm = normalize_url(val)["normalized"]
                    urls_set.add(u_norm)
                    u_node_id = f"url_{u_norm[:40]}"
                    if u_node_id not in seen_nodes:
                        nodes.append({"id": u_node_id, "type": "URL", "label": u_norm[:35]})
                        seen_nodes.add(u_node_id)
                    edges.append({"source": case_node_id, "target": u_node_id, "relation": "OBSERVED_URL", "strength": "STRONG"})

        return {
            "campaign": camp,
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "cases_count": len(cases),
                "domains": sorted(list(domains_set)),
                "ips": sorted(list(ips_set)),
                "urls": sorted(list(urls_set)),
                "reply_tos": sorted(list(reply_tos_set)),
                "senders": sorted(list(senders_set))
            }
        }

    # -----------------------------------------------------------------------
    # Campaign Timeline (Chronological Foundation)
    # -----------------------------------------------------------------------
    def get_campaign_timeline(self, campaign_id: str) -> List[Dict[str, Any]]:
        """
        Builds chronological timeline events from actual stored case and email data.
        """
        camps = supabase.query("campaigns", select="*", filters={"id": f"eq.{campaign_id}"})
        if not camps:
            camps = supabase.query("campaigns", select="*", filters={"campaign_id": f"eq.{campaign_id}"})
        if not camps:
            return []

        camp = camps[0]
        c_uuid = camp.get("id")
        cases = supabase.query("cases", select="*", filters={"campaign_id": f"eq.{c_uuid}"})

        events: List[Dict[str, Any]] = []

        # 1. Timeline events recorded during ingestion
        cached_events = supabase.query("campaign_timeline", select="*", filters={"campaign_id": f"eq.{c_uuid}"})
        events.extend(cached_events)

        # 2. Real events from cases and emails
        for case in cases:
            case_id = case.get("id") or case.get("case_number")
            events.append({
                "id": f"evt_case_{case_id}",
                "campaign_id": c_uuid,
                "case_id": case_id,
                "event_type": "CASE_REGISTERED",
                "timestamp": case.get("created_at"),
                "title": f"Investigation {case.get('case_number')} Ingested",
                "description": f"Forensic investigation initiated for '{case.get('title', '')[:50]}'. Risk Score: {case.get('risk_score')}/100.",
                "signals": []
            })

            # Check for probable IP
            if case.get("probable_origin_ip"):
                events.append({
                    "id": f"evt_ip_{case_id}",
                    "campaign_id": c_uuid,
                    "case_id": case_id,
                    "event_type": "IP_OBSERVED",
                    "timestamp": case.get("created_at"),
                    "title": f"Origin IP Observed ({case.get('probable_origin_ip')})",
                    "description": f"Network transit origin IP isolated. Location: {case.get('approximate_location', 'Unknown')}.",
                    "signals": []
                })

            # Fetch emails
            emails = supabase.query("emails", select="*", filters={"case_id": f"eq.{case_id}"})
            for eml in emails:
                if eml.get("reply_to"):
                    events.append({
                        "id": f"evt_reply_{eml.get('id')}",
                        "campaign_id": c_uuid,
                        "case_id": case_id,
                        "event_type": "REPLY_TO_OBSERVED",
                        "timestamp": case.get("created_at"),
                        "title": f"Reply-To Address Observed",
                        "description": f"Message directs responses to '{eml.get('reply_to')}'.",
                        "signals": []
                    })

        # Deduplicate and sort chronologically
        unique_events = {}
        for ev in events:
            ev_id = ev.get("id")
            if ev_id not in unique_events:
                unique_events[ev_id] = ev

        sorted_events = sorted(
            unique_events.values(),
            key=lambda x: str(x.get("timestamp", ""))
        )
        return sorted_events


campaign_service = CampaignCorrelationService()
