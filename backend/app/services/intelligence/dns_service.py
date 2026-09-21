"""
Authoritative DNS & MX Query Engine.
Resolves A, AAAA, MX, NS, TXT, and CNAME records with strict timeouts using dnspython.
Identifies enterprise mail infrastructure from MX routing without assuming maliciousness.
"""
import socket
import logging
from typing import Dict, Any, List, Optional
import dns.resolver
import dns.exception
from app.services.intelligence.base import (
    BaseEnrichmentResult,
    IntelligenceStatus,
    EvidenceNature,
    BaseIntelligenceProvider
)
from app.services.intelligence.cache import intelligence_cache

logger = logging.getLogger("ANVESH.DNS")

KNOWN_MX_PROVIDERS = [
    ("MICROSOFT_365", ["protection.outlook.com", "mail.eo.outlook.com", "outlook.com"]),
    ("GOOGLE_WORKSPACE", ["aspmx.l.google.com", "googlemail.com", "google.com"]),
    ("PROOFPOINT", ["pphosted.com", "proofpoint.com"]),
    ("MIMECAST", ["mimecast.com"]),
    ("PROTONMAIL", ["protonmail.ch", "proton.me"]),
    ("ZOHO_MAIL", ["zoho.com", "zoho.in"]),
    ("AMAZON_SES", ["amazonses.com", "aws.amazon.com"]),
    ("CISCO_IRONPORT", ["iphmx.com", "ironport.com"]),
    ("BARRACUDA", ["barracudanetworks.com", "ess.barracuda.com"])
]


class DNSService(BaseIntelligenceProvider):
    def __init__(self):
        super().__init__(name="AUTHORITATIVE_DNS")
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = 2.5
        self._resolver.lifetime = 2.5

    def resolve_domain(self, domain: str) -> BaseEnrichmentResult:
        clean_domain = domain.strip().lower()
        if not clean_domain or "." not in clean_domain:
            return self.get_error_result(clean_domain, "DOMAIN", "Invalid domain name syntax for DNS resolution")

        cached = intelligence_cache.get(clean_domain, self.name, "DNS_RECORDS")
        if cached:
            return cached

        records: Dict[str, List[Any]] = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": []
        }

        detected_mail_provider = None
        has_any_record = False

        for r_type in ["A", "AAAA", "MX", "NS", "TXT"]:
            try:
                answers = self._resolver.resolve(clean_domain, r_type)
                for rdata in answers:
                    has_any_record = True
                    if r_type == "MX":
                        exchange = str(rdata.exchange).rstrip('.').lower()
                        prio = int(rdata.preference)
                        resolved_ip = None
                        try:
                            resolved_ip = socket.gethostbyname(exchange)
                        except Exception:
                            pass
                        
                        # Identify known MX provider
                        provider_name = "Self-Hosted / Independent Provider"
                        for p_label, patterns in KNOWN_MX_PROVIDERS:
                            if any(pat in exchange for pat in patterns):
                                provider_name = p_label
                                detected_mail_provider = p_label
                                break

                        records["MX"].append({
                            "exchange": exchange,
                            "preference": prio,
                            "resolved_ip": resolved_ip,
                            "mail_provider": provider_name
                        })
                    elif r_type in ("A", "AAAA"):
                        records[r_type].append(str(rdata.address))
                    elif r_type == "NS":
                        records["NS"].append(str(rdata.target).rstrip('.'))
                    elif r_type == "TXT":
                        txt_str = "".join([part.decode('utf-8', errors='replace') for part in rdata.strings])
                        records["TXT"].append(txt_str[:250])  # limit length
            except dns.resolver.NXDOMAIN:
                return self.get_no_data_result(clean_domain, "DOMAIN", f"Domain {clean_domain} does not exist (NXDOMAIN)")
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
            except dns.exception.Timeout:
                logger.debug(f"DNS timeout querying {r_type} for {clean_domain}")
                continue
            except Exception as e:
                logger.debug(f"DNS query error {r_type} for {clean_domain}: {e}")
                continue

        # Also check CNAME if no A record
        if not records["A"]:
            try:
                answers = self._resolver.resolve(clean_domain, "CNAME")
                for rdata in answers:
                    has_any_record = True
                    records["CNAME"].append(str(rdata.target).rstrip('.'))
            except Exception:
                pass

        if not has_any_record:
            res = self.get_no_data_result(clean_domain, "DOMAIN", "No DNS resource records returned for domain.")
            intelligence_cache.set(res, "DNS_RECORDS", ttl_seconds=300)
            return res

        res_data = {
            "domain": clean_domain,
            "records": records,
            "detected_mail_provider": detected_mail_provider or "INDEPENDENT_OR_UNCLASSIFIED",
            "has_mx": len(records["MX"]) > 0,
            "has_spf": any("v=spf1" in txt.lower() for txt in records["TXT"]),
            "has_dmarc": False  # can be verified via _dmarc subdomain
        }

        # Query DMARC record specifically: _dmarc.<domain>
        try:
            dmarc_answers = self._resolver.resolve(f"_dmarc.{clean_domain}", "TXT")
            for rdata in dmarc_answers:
                txt_str = "".join([part.decode('utf-8', errors='replace') for part in rdata.strings])
                if "v=dmarc1" in txt_str.lower():
                    res_data["has_dmarc"] = True
                    res_data["dmarc_record"] = txt_str
                    break
        except Exception:
            pass

        result = BaseEnrichmentResult(
            indicator=clean_domain,
            indicator_type="DOMAIN",
            status=IntelligenceStatus.OBSERVED,
            provider=self.name,
            source="AUTHORITATIVE_DNS_RESOLVER",
            evidence_nature=EvidenceNature.OBSERVED,
            confidence="HIGH",
            disclaimer="Authoritative DNS resource records. DNS presence alone is not indicative of maliciousness.",
            data=res_data
        )
        intelligence_cache.set(result, "DNS_RECORDS", ttl_seconds=3600)
        return result


dns_service = DNSService()
