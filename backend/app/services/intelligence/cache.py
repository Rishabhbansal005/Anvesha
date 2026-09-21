"""
Thread-safe in-memory TTL cache with Supabase lookup persistence.
Ensures external rate limits are respected and identical indicators are not re-queried redundantly.
Never caches secrets.
"""
import threading
import time
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from app.services.intelligence.base import BaseEnrichmentResult, IntelligenceStatus
from app.database.supabase_client import supabase


class IntelligenceCache:
    def __init__(self, default_ttl_seconds: int = 3600):
        self._lock = threading.Lock()
        self._cache: Dict[Tuple[str, str, str], Tuple[float, BaseEnrichmentResult]] = {}
        self._default_ttl = default_ttl_seconds

    def _make_key(self, indicator: str, provider: str, lookup_type: str) -> Tuple[str, str, str]:
        return (indicator.strip().lower(), provider.strip().upper(), lookup_type.strip().upper())

    def get(self, indicator: str, provider: str, lookup_type: str) -> Optional[BaseEnrichmentResult]:
        key = self._make_key(indicator, provider, lookup_type)
        now = time.time()
        
        with self._lock:
            if key in self._cache:
                expires_at, result = self._cache[key]
                if now < expires_at:
                    return result
                else:
                    del self._cache[key]
                    
        # Check Supabase enrichment_lookups if configured
        try:
            rows = supabase.query(
                "enrichment_lookups",
                filters={
                    "indicator": f"eq.{indicator.strip().lower()}",
                    "provider": f"eq.{provider.strip().upper()}"
                },
                limit=1
            )
            matching = [
                r for r in rows
                if r.get("indicator", "").strip().lower() == indicator.strip().lower()
                and r.get("provider", "").strip().upper() == provider.strip().upper()
            ]
            if matching:
                row = matching[0]
                exp_str = row.get("expires_at")
                if exp_str:
                    exp_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                    if exp_dt > datetime.utcnow():
                        res = BaseEnrichmentResult(
                            indicator=row.get("indicator"),
                            indicator_type=row.get("indicator_type"),
                            status=IntelligenceStatus(row.get("status", "ENRICHED")),
                            provider=row.get("provider"),
                            source=row.get("source", "CACHE"),
                            evidence_nature=row.get("evidence_nature", "DERIVED"),
                            lookup_timestamp=row.get("fetched_at"),
                            data=row.get("result_data", {}),
                            error_message=row.get("error_message")
                        )
                        with self._lock:
                            self._cache[key] = (now + self._default_ttl, res)
                        return res
        except Exception:
            pass

        return None

    def set(self, result: BaseEnrichmentResult, lookup_type: str, ttl_seconds: Optional[int] = None) -> None:
        key = self._make_key(result.indicator, result.provider, lookup_type)
        ttl = ttl_seconds or self._default_ttl
        now = time.time()
        expires_at = now + ttl

        with self._lock:
            self._cache[key] = (expires_at, result)

        # Store into database ledger for auditability
        try:
            exp_iso = (datetime.utcnow() + timedelta(seconds=ttl)).isoformat()
            row = {
                "indicator": result.indicator.strip().lower(),
                "indicator_type": result.indicator_type,
                "provider": result.provider.strip().upper(),
                "status": result.status.value,
                "evidence_nature": result.evidence_nature.value,
                "result_data": result.data,
                "error_message": result.error_message,
                "source": result.source,
                "fetched_at": result.lookup_timestamp,
                "expires_at": exp_iso
            }
            supabase.insert("enrichment_lookups", row)
        except Exception:
            pass

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
        if hasattr(supabase, "_local_cache") and "enrichment_lookups" in supabase._local_cache:
            supabase._local_cache["enrichment_lookups"] = []


intelligence_cache = IntelligenceCache()
