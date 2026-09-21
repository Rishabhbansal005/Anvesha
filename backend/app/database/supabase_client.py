import time
import logging
from typing import List, Dict, Any, Optional
import httpx
from app.core.config import settings

logger = logging.getLogger("ANVESH.Supabase")


class SupabaseClient:
    def __init__(self):
        self.base_url = settings.SUPABASE_URL.rstrip('/')
        self.rest_url = f"{self.base_url}/rest/v1"
        self.secret_key = settings.SUPABASE_SECRET_KEY
        self.publishable_key = settings.SUPABASE_PUBLISHABLE_KEY
        self._missing_tables: Dict[str, float] = {}
        self._local_cache: Dict[str, List[Dict[str, Any]]] = {
            "cases": [],
            "emails": [],
            "evidence": [],
            "alerts": [],
            "campaigns": [],
            "iocs": [],
            "enrichment_lookups": [],
            "infrastructure_intelligence": [],
            "dns_records": [],
            "rdap_records": [],
            "threat_intelligence_observations": [],
            "attribution_assessments": [],
            "evidence_gaps": [],
            "campaign_correlations": [],
            "campaign_timeline": [],
            "case_notes": [],
            "case_decisions": [],
            "case_activities": []
        }
        
        self.headers = {
            "apikey": self.secret_key or self.publishable_key,
            "Authorization": f"Bearer {self.secret_key or self.publishable_key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation"
        }
        
        # Shared connection-pooled HTTP client with low timeout to prevent network stalls
        self._client = httpx.Client(
            timeout=1.5,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50)
        )
        
    def is_configured(self) -> bool:
        return bool(self.base_url and (self.secret_key or self.publishable_key))

    def ping(self) -> bool:
        """Pings Supabase REST gateway to verify connectivity."""
        if not self.is_configured():
            return False
        try:
            r = self._client.get(f"{self.rest_url}/", headers=self.headers)
            return r.status_code == 200
        except Exception as e:
            logger.warning(f"Supabase ping failed: {e}")
            return False

    def query(self, table: str, select: str = "*", filters: Optional[Dict[str, str]] = None, order: Optional[str] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Queries rows from Supabase table, with automatic fallback cache if table schema not yet migrated."""
        # Fast path: If table was previously detected as 404 (not migrated), serve directly from memory cache in 0.01ms
        now = time.time()
        if table in self._missing_tables and now < self._missing_tables[table]:
            return self._query_local_cache(table, filters=filters, limit=limit)

        if not self.is_configured():
            return self._query_local_cache(table, filters=filters, limit=limit)
            
        params = {"select": select}
        if filters:
            for k, v in filters.items():
                params[k] = v
        if order:
            params["order"] = order
        if limit:
            params["limit"] = str(limit)

        try:
            r = self._client.get(f"{self.rest_url}/{table}", headers=self.headers, params=params)
            if r.status_code == 200:
                rows = r.json()
                local_rows = self._local_cache.get(table, [])
                if local_rows:
                    existing_ids = {row.get("id") or row.get("case_number") for row in rows}
                    for lr in local_rows:
                        if (lr.get("id") or lr.get("case_number")) not in existing_ids:
                            rows.append(lr)
                return rows
            elif r.status_code in (404, 400):
                # Table not migrated in Supabase PostgREST: remember for 10 minutes to avoid repeated slow HTTP roundtrips
                self._missing_tables[table] = now + 600.0
                return self._query_local_cache(table, filters=filters, limit=limit)
            else:
                return self._query_local_cache(table, filters=filters, limit=limit)
        except Exception as e:
            logger.warning(f"Supabase query error on {table}: {e}")
            return self._query_local_cache(table, filters=filters, limit=limit)

    def _query_local_cache(self, table: str, filters: Optional[Dict[str, str]] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        rows = self._local_cache.get(table, [])
        if not filters:
            return rows[:limit] if limit else rows
        
        filtered = []
        for r in rows:
            match = True
            for k, v in filters.items():
                val = v
                if val.startswith("eq."):
                    val = val[3:]
                if str(r.get(k, "")) != str(val):
                    match = False
                    break
            if match:
                filtered.append(r)
        return filtered[:limit] if limit else filtered

    def count(self, table: str, filters: Optional[Dict[str, str]] = None) -> int:
        return len(self.query(table, filters=filters))

    def insert(self, table: str, row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Inserts a single row into Supabase and returns the created record."""
        # Always track in local cache so analyzed data is immediately visible in UI
        if table in self._local_cache:
            self._local_cache[table].insert(0, row)

        now = time.time()
        if table in self._missing_tables and now < self._missing_tables[table]:
            return row

        if not self.is_configured():
            return row
            
        try:
            r = self._client.post(f"{self.rest_url}/{table}", headers=self.headers, json=row)
            if r.status_code in (200, 201):
                res = r.json()
                return res[0] if isinstance(res, list) and len(res) > 0 else res
            elif r.status_code in (404, 400):
                self._missing_tables[table] = now + 600.0
                return row
            return row
        except Exception as e:
            logger.warning(f"Supabase insert error on {table}: {e}")
            return row

    def insert_batch(self, table: str, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch inserts multiple rows in a single HTTP request for high-performance observable ingestion."""
        if not rows:
            return []

        # Always track in local cache
        if table in self._local_cache:
            for row in reversed(rows):
                self._local_cache[table].insert(0, row)

        now = time.time()
        if table in self._missing_tables and now < self._missing_tables[table]:
            return rows

        if not self.is_configured():
            return rows

        try:
            r = self._client.post(f"{self.rest_url}/{table}", headers=self.headers, json=rows)
            if r.status_code in (200, 201):
                res = r.json()
                return res if isinstance(res, list) else rows
            elif r.status_code in (404, 400):
                self._missing_tables[table] = now + 600.0
                return rows
            return rows
        except Exception as e:
            logger.warning(f"Supabase insert_batch error on {table}: {e}")
            return rows

    def update(self, table: str, match_col: str, match_val: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Updates matching rows in Supabase and local cache."""
        updated_row = None
        if table in self._local_cache:
            for row in self._local_cache[table]:
                if str(row.get(match_col)) == str(match_val):
                    row.update(updates)
                    updated_row = row

        now = time.time()
        if table in self._missing_tables and now < self._missing_tables[table]:
            return updated_row

        if not self.is_configured():
            return updated_row
        try:
            params = {f"{match_col}": f"eq.{match_val}"}
            r = self._client.patch(f"{self.rest_url}/{table}", headers=self.headers, params=params, json=updates)
            if r.status_code == 200:
                res = r.json()
                return res[0] if isinstance(res, list) and len(res) > 0 else res
            elif r.status_code in (404, 400):
                self._missing_tables[table] = now + 600.0
                return updated_row
            return updated_row
        except Exception as e:
            logger.warning(f"Supabase update error on {table}: {e}")
            return updated_row


supabase = SupabaseClient()
