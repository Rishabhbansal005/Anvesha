"""
Threat Intelligence Provider Abstraction & Real Feed Integrations.
Strict Zero-Fabrication Contract:
If API keys (VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, SAFE_BROWSING_API_KEY) are missing or empty,
returns explicit status='UNAVAILABLE' with objective explanation.
Never fabricates detection ratios, abuse confidence scores, or fake reputation verdicts.
"""
import logging
from typing import Dict, Any, Optional, List
import httpx
from app.core.config import settings
from app.services.intelligence.base import (
    BaseEnrichmentResult,
    IntelligenceStatus,
    EvidenceNature,
    BaseIntelligenceProvider,
    ThreatVerdict
)
from app.services.intelligence.cache import intelligence_cache

logger = logging.getLogger("ANVESH.ThreatIntel")


class VirusTotalProvider(BaseIntelligenceProvider):
    def __init__(self):
        super().__init__(name="VIRUSTOTAL")
        self._api_key: Optional[str] = None

    @property
    def api_key(self) -> str:
        if self._api_key is not None:
            return self._api_key
        import os
        return os.environ.get("VIRUSTOTAL_API_KEY", "").strip() or getattr(settings, "VIRUSTOTAL_API_KEY", "").strip()

    @api_key.setter
    def api_key(self, val: str):
        self._api_key = val

    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key) > 8)

    def lookup_ip(self, ip_str: str) -> BaseEnrichmentResult:
        clean_ip = ip_str.strip()
        if not self.is_configured():
            return self.get_unconfigured_result(clean_ip, "IP", "VirusTotal API key (VIRUSTOTAL_API_KEY) not configured.")

        cached = intelligence_cache.get(clean_ip, self.name, "VT_IP")
        if cached:
            return cached

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{clean_ip}"
        headers = {"x-apikey": self.api_key}

        try:
            with httpx.Client(timeout=4.0) as client:
                r = client.get(url, headers=headers)
                if r.status_code == 200:
                    data = r.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 0
                    
                    verdict = ThreatVerdict.CLEAN
                    if malicious >= 3:
                        verdict = ThreatVerdict.MALICIOUS
                    elif malicious > 0 or suspicious > 0:
                        verdict = ThreatVerdict.SUSPICIOUS

                    res_data = {
                        "indicator": clean_ip,
                        "verdict": verdict.value,
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "total_engines": total,
                        "reputation": data.get("reputation", 0),
                        "network": data.get("network"),
                        "as_owner": data.get("as_owner"),
                        "reference_url": f"https://www.virustotal.com/gui/ip-address/{clean_ip}"
                    }
                    res = BaseEnrichmentResult(
                        indicator=clean_ip,
                        indicator_type="IP",
                        status=IntelligenceStatus.ENRICHED,
                        provider=self.name,
                        source="VIRUSTOTAL_API_V3",
                        evidence_nature=EvidenceNature.DERIVED,
                        confidence="HIGH" if total > 20 else "MEDIUM",
                        disclaimer="Third-party multi-engine reputation analysis.",
                        data=res_data
                    )
                    intelligence_cache.set(res, "VT_IP", ttl_seconds=86400)
                    return res
                elif r.status_code == 404:
                    return self.get_no_data_result(clean_ip, "IP", "No intelligence record found in VirusTotal dataset.")
                else:
                    return self.get_error_result(clean_ip, "IP", f"VirusTotal API returned HTTP {r.status_code}")
        except httpx.TimeoutException:
            return self.get_error_result(clean_ip, "IP", "VirusTotal API connection timed out.")
        except Exception as e:
            return self.get_error_result(clean_ip, "IP", f"VirusTotal lookup error: {str(e)}")


class AbuseIPDBProvider(BaseIntelligenceProvider):
    def __init__(self):
        super().__init__(name="ABUSEIPDB")
        self._api_key: Optional[str] = None

    @property
    def api_key(self) -> str:
        if self._api_key is not None:
            return self._api_key
        import os
        return os.environ.get("ABUSEIPDB_API_KEY", "").strip() or getattr(settings, "ABUSEIPDB_API_KEY", "").strip()

    @api_key.setter
    def api_key(self, val: str):
        self._api_key = val

    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key) > 8)

    def lookup_ip(self, ip_str: str) -> BaseEnrichmentResult:
        clean_ip = ip_str.strip()
        if not self.is_configured():
            return self.get_unconfigured_result(clean_ip, "IP", "AbuseIPDB API key (ABUSEIPDB_API_KEY) not configured.")

        cached = intelligence_cache.get(clean_ip, self.name, "ABUSE_IP")
        if cached:
            return cached

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": clean_ip, "maxAgeInDays": 90}

        try:
            with httpx.Client(timeout=4.0) as client:
                r = client.get(url, headers=headers, params=params)
                if r.status_code == 200:
                    data = r.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    reports = data.get("totalReports", 0)
                    is_tor = data.get("isTor", False)

                    verdict = ThreatVerdict.CLEAN
                    if score >= 50:
                        verdict = ThreatVerdict.MALICIOUS
                    elif score > 10:
                        verdict = ThreatVerdict.SUSPICIOUS

                    res_data = {
                        "indicator": clean_ip,
                        "verdict": verdict.value,
                        "abuse_confidence_score": score,
                        "total_reports": reports,
                        "is_tor_node": is_tor,
                        "usage_type": data.get("usageType"),
                        "domain": data.get("domain"),
                        "country_code": data.get("countryCode"),
                        "reference_url": f"https://www.abuseipdb.com/check/{clean_ip}"
                    }
                    res = BaseEnrichmentResult(
                        indicator=clean_ip,
                        indicator_type="IP",
                        status=IntelligenceStatus.ENRICHED,
                        provider=self.name,
                        source="ABUSEIPDB_V2",
                        evidence_nature=EvidenceNature.DERIVED,
                        confidence="HIGH" if reports > 5 else "MEDIUM",
                        disclaimer="Community abuse reports and IP reputation metrics.",
                        data=res_data
                    )
                    intelligence_cache.set(res, "ABUSE_IP", ttl_seconds=86400)
                    return res
                elif r.status_code == 404:
                    return self.get_no_data_result(clean_ip, "IP", "No abuse reports on record in AbuseIPDB database.")
                else:
                    return self.get_error_result(clean_ip, "IP", f"AbuseIPDB API returned HTTP {r.status_code}")
        except httpx.TimeoutException:
            return self.get_error_result(clean_ip, "IP", "AbuseIPDB request timed out.")
        except Exception as e:
            return self.get_error_result(clean_ip, "IP", f"AbuseIPDB query error: {str(e)}")


class SafeBrowsingProvider(BaseIntelligenceProvider):
    def __init__(self):
        super().__init__(name="SAFE_BROWSING")
        self._api_key: Optional[str] = None

    @property
    def api_key(self) -> str:
        if self._api_key is not None:
            return self._api_key
        import os
        return os.environ.get("SAFE_BROWSING_API_KEY", "").strip() or getattr(settings, "SAFE_BROWSING_API_KEY", "").strip()

    @api_key.setter
    def api_key(self, val: str):
        self._api_key = val

    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key) > 8)

    def check_url(self, url_str: str) -> BaseEnrichmentResult:
        clean_url = url_str.strip()
        if not self.is_configured():
            return self.get_unconfigured_result(clean_url, "URL", "Google Safe Browsing API key (SAFE_BROWSING_API_KEY) not configured.")

        cached = intelligence_cache.get(clean_url, self.name, "GSB_URL")
        if cached:
            return cached

        api_endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {"clientId": "anvesh-forensic", "clientVersion": "3.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": clean_url}]
            }
        }

        try:
            with httpx.Client(timeout=3.5) as client:
                r = client.post(api_endpoint, json=payload)
                if r.status_code == 200:
                    res_body = r.json()
                    matches = res_body.get("matches", [])
                    has_match = len(matches) > 0
                    verdict = ThreatVerdict.MALICIOUS if has_match else ThreatVerdict.CLEAN
                    
                    res_data = {
                        "indicator": clean_url,
                        "verdict": verdict.value,
                        "threat_matches": [m.get("threatType") for m in matches],
                        "platform": [m.get("platformType") for m in matches]
                    }
                    res = BaseEnrichmentResult(
                        indicator=clean_url,
                        indicator_type="URL",
                        status=IntelligenceStatus.ENRICHED,
                        provider=self.name,
                        source="GOOGLE_SAFE_BROWSING_V4",
                        evidence_nature=EvidenceNature.DERIVED,
                        confidence="HIGH",
                        disclaimer="Authoritative URL threat list match.",
                        data=res_data
                    )
                    intelligence_cache.set(res, "GSB_URL", ttl_seconds=86400)
                    return res
                else:
                    return self.get_error_result(clean_url, "URL", f"Safe Browsing API returned HTTP {r.status_code}")
        except httpx.TimeoutException:
            return self.get_error_result(clean_url, "URL", "Google Safe Browsing API connection timed out.")
        except Exception as e:
            return self.get_error_result(clean_url, "URL", f"Safe Browsing check error: {str(e)}")


vt_provider = VirusTotalProvider()
abuseipdb_provider = AbuseIPDBProvider()
safebrowsing_provider = SafeBrowsingProvider()
