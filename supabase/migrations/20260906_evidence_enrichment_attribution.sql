-- ============================================================================
-- ANVESH: Cyber Forensic Intelligence Platform
-- Problem Statement: SIH26106 | Phase 3 Migration: Evidence Enrichment & Attribution
-- ============================================================================

-- 1. ENRICHMENT LOOKUPS (Intelligence Cache & Provider Traceability)
CREATE TABLE IF NOT EXISTS public.enrichment_lookups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL, -- IP, DOMAIN, URL, HASH
    provider TEXT NOT NULL,       -- IANA_RDAP, DNS_RESOLVER, VIRUSTOTAL, ABUSEIPDB, etc.
    status TEXT NOT NULL,         -- OBSERVED, ENRICHED, UNAVAILABLE, NO_DATA, ERROR
    evidence_nature TEXT NOT NULL DEFAULT 'DERIVED', -- OBSERVED, DERIVED
    result_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT,
    source TEXT NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    CONSTRAINT uq_indicator_provider_lookup UNIQUE (indicator, indicator_type, provider)
);

-- 2. INFRASTRUCTURE INTELLIGENCE (IP / Host Infrastructure Records)
CREATE TABLE IF NOT EXISTS public.infrastructure_intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID REFERENCES public.cases(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL,
    ip_version INTEGER NOT NULL DEFAULT 4, -- 4, 6
    is_private BOOLEAN NOT NULL DEFAULT FALSE,
    country TEXT,
    region TEXT,
    city TEXT,
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    asn TEXT,
    isp TEXT,
    organization TEXT,
    hosting_provider TEXT,
    cloud_classification TEXT, -- MICROSOFT_365, GOOGLE_WORKSPACE, AWS, AZURE, CLOUDFLARE, DIGITALOCEAN, OVH, HETZNER, FASTLY, AKAMAI, RESIDENTIAL, UNKNOWN
    classification_source TEXT, -- e.g. "AUTHORITATIVE_ASN_AS8075", "BGP_PREFIX_RDAP"
    vpn_tor_proxy_indicator TEXT NOT NULL DEFAULT 'NONE', -- NONE, TOR_EXIT_RELAY, VPN_RELAY, PROXY, HOSTING_GATEWAY, UNAVAILABLE
    reputation TEXT DEFAULT 'UNKNOWN',
    status TEXT NOT NULL DEFAULT 'OBSERVED', -- OBSERVED, ENRICHED, UNAVAILABLE, NO_DATA, ERROR
    evidence_nature TEXT NOT NULL DEFAULT 'DERIVED',
    provider TEXT NOT NULL DEFAULT 'AUTHORITATIVE_REGISTRY',
    disclaimer TEXT NOT NULL DEFAULT 'IP-associated infrastructure location. Does not establish physical actor location.',
    lookup_timestamp TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 3. DNS RECORDS (Authoritative DNS & MX Query Intelligence)
CREATE TABLE IF NOT EXISTS public.dns_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID REFERENCES public.cases(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    record_type TEXT NOT NULL, -- A, AAAA, MX, NS, TXT, CNAME
    record_value TEXT NOT NULL,
    priority INTEGER,
    ttl INTEGER,
    resolved_ip TEXT,
    mail_provider TEXT,
    status TEXT NOT NULL DEFAULT 'OBSERVED', -- OBSERVED, NO_DATA, ERROR
    evidence_nature TEXT NOT NULL DEFAULT 'OBSERVED',
    source TEXT NOT NULL DEFAULT 'AUTHORITATIVE_DNS_RESOLVER',
    last_checked TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 4. RDAP RECORDS (Standards-based RFC 7484 Registration Data)
CREATE TABLE IF NOT EXISTS public.rdap_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID REFERENCES public.cases(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL, -- DOMAIN, IP
    registrar TEXT,
    registered_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    domain_status TEXT[] DEFAULT '{}',
    nameservers TEXT[] DEFAULT '{}',
    abuse_contact TEXT,
    raw_rdap JSONB DEFAULT '{}'::jsonb,
    lookup_source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ENRICHED', -- ENRICHED, UNAVAILABLE, NO_DATA, ERROR
    evidence_nature TEXT NOT NULL DEFAULT 'DERIVED',
    lookup_timestamp TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 5. THREAT INTELLIGENCE OBSERVATIONS (External Reputation & Feeds)
CREATE TABLE IF NOT EXISTS public.threat_intelligence_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID REFERENCES public.cases(id) ON DELETE CASCADE,
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL, -- IP, DOMAIN, URL, HASH
    provider TEXT NOT NULL,       -- VIRUSTOTAL, ABUSEIPDB, SAFE_BROWSING
    verdict TEXT NOT NULL,        -- CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN, UNAVAILABLE
    confidence TEXT NOT NULL DEFAULT 'MEDIUM', -- HIGH, MEDIUM, LOW, NONE
    score INTEGER,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    reference_url TEXT,
    details JSONB DEFAULT '{}'::jsonb,
    status TEXT NOT NULL,         -- OBSERVED, UNAVAILABLE, NO_DATA, ERROR
    evidence_nature TEXT NOT NULL DEFAULT 'DERIVED',
    lookup_timestamp TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 6. ATTRIBUTION ASSESSMENTS (Attribution Boundary & Transparent Limits)
CREATE TABLE IF NOT EXISTS public.attribution_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    threat_risk TEXT NOT NULL,
    observed_infrastructure TEXT NOT NULL,
    origin_confidence TEXT NOT NULL, -- HIGH, MEDIUM, LOW, UNDETERMINED
    actor_identity TEXT NOT NULL DEFAULT 'NOT ESTABLISHED',
    attribution_boundary TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_nature TEXT NOT NULL DEFAULT 'DERIVED',
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 7. EVIDENCE GAPS (Missing Forensic Artifacts & Recommended Next Steps)
CREATE TABLE IF NOT EXISTS public.evidence_gaps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    current_evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    identified_gaps JSONB NOT NULL DEFAULT '[]'::jsonb,
    additional_evidence_options JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommended_next_action TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- ----------------------------------------------------------------------------
-- INDEXES FOR RETRIEVAL EFFICIENCY
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_infra_case ON public.infrastructure_intelligence(case_id);
CREATE INDEX IF NOT EXISTS idx_infra_ip ON public.infrastructure_intelligence(ip_address);
CREATE INDEX IF NOT EXISTS idx_dns_case ON public.dns_records(case_id);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON public.dns_records(domain);
CREATE INDEX IF NOT EXISTS idx_rdap_case ON public.rdap_records(case_id);
CREATE INDEX IF NOT EXISTS idx_rdap_target ON public.rdap_records(target);
CREATE INDEX IF NOT EXISTS idx_threat_case ON public.threat_intelligence_observations(case_id);
CREATE INDEX IF NOT EXISTS idx_threat_indicator ON public.threat_intelligence_observations(indicator);
CREATE INDEX IF NOT EXISTS idx_attribution_case ON public.attribution_assessments(case_id);
CREATE INDEX IF NOT EXISTS idx_gaps_case ON public.evidence_gaps(case_id);
CREATE INDEX IF NOT EXISTS idx_cache_indicator ON public.enrichment_lookups(indicator, provider);

-- ----------------------------------------------------------------------------
-- ROW LEVEL SECURITY (RLS)
-- ----------------------------------------------------------------------------
ALTER TABLE public.enrichment_lookups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.infrastructure_intelligence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dns_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rdap_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_intelligence_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attribution_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence_gaps ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service Role Full Access Enrichment Lookups" ON public.enrichment_lookups FOR ALL USING (true);
CREATE POLICY "Service Role Full Access Infra Intel" ON public.infrastructure_intelligence FOR ALL USING (true);
CREATE POLICY "Service Role Full Access DNS Records" ON public.dns_records FOR ALL USING (true);
CREATE POLICY "Service Role Full Access RDAP Records" ON public.rdap_records FOR ALL USING (true);
CREATE POLICY "Service Role Full Access Threat Intel" ON public.threat_intelligence_observations FOR ALL USING (true);
CREATE POLICY "Service Role Full Access Attribution" ON public.attribution_assessments FOR ALL USING (true);
CREATE POLICY "Service Role Full Access Evidence Gaps" ON public.evidence_gaps FOR ALL USING (true);
