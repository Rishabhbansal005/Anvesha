-- ============================================================================
-- ANVESH: Cyber Forensic Intelligence Platform
-- Problem Statement: SIH26106 | Supabase Database Schema & Initial Migration
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- 1. PROFILES (SOC Analysts & Investigators)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_user_id UUID UNIQUE,
    full_name TEXT NOT NULL,
    badge_number TEXT,
    role TEXT NOT NULL DEFAULT 'ANALYST', -- ANALYST, SENIOR_INVESTIGATOR, LEAD_SOC
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- ----------------------------------------------------------------------------
-- 2. CAMPAIGNS (Correlated Threat Infrastructure)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    threat_cluster TEXT,
    threat_type TEXT NOT NULL DEFAULT 'BEC', -- BEC, CREDENTIAL_PHISHING, EXTORTION
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'HIGH', -- CRITICAL, HIGH, MEDIUM, LOW
    confidence_score INTEGER NOT NULL DEFAULT 75,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- ----------------------------------------------------------------------------
-- 3. CASES & INVESTIGATIONS
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_number TEXT NOT NULL UNIQUE, -- e.g. "ANV-2026-0001"
    title TEXT NOT NULL,
    description TEXT,
    risk_score INTEGER NOT NULL DEFAULT 0, -- 0 to 100
    risk_level TEXT NOT NULL DEFAULT 'INFORMATIONAL', -- CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    threat_type TEXT NOT NULL DEFAULT 'SPAM_BENIGN',
    status TEXT NOT NULL DEFAULT 'NEW', -- NEW, UNDER_REVIEW, ESCALATED, RESOLVED, FALSE_POSITIVE
    
    -- Forensic Origin (Strictly Evidentiary Language)
    probable_origin_ip TEXT,
    origin_confidence TEXT NOT NULL DEFAULT 'LOW', -- HIGH, MEDIUM, LOW, UNRELIABLE
    approximate_location TEXT, -- e.g. "Amsterdam, Netherlands"
    
    assigned_to UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    campaign_id UUID REFERENCES public.campaigns(id) ON DELETE SET NULL,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- ----------------------------------------------------------------------------
-- 4. EMAILS & RFC-822 RECORDS
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.emails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    message_id TEXT,
    subject TEXT NOT NULL,
    sender TEXT NOT NULL,
    sender_display TEXT,
    return_path TEXT,
    reply_to TEXT,
    recipient TEXT NOT NULL,
    
    -- Hashes
    body_hash_sha256 TEXT,
    raw_header_sha256 TEXT,
    
    -- Cryptographic Authentication Results
    spf_status TEXT NOT NULL DEFAULT 'NONE', -- PASS, FAIL, SOFTFAIL, NONE
    spf_details TEXT,
    dkim_status TEXT NOT NULL DEFAULT 'NONE', -- PASS, FAIL, NONE
    dkim_details TEXT,
    dmarc_status TEXT NOT NULL DEFAULT 'NONE', -- PASS, FAIL, NONE
    dmarc_details TEXT,
    
    -- Reconstructed Routing Data
    relay_count INTEGER NOT NULL DEFAULT 0,
    delivery_hops_json JSONB DEFAULT '[]'::jsonb,
    raw_headers TEXT,
    
    received_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- ----------------------------------------------------------------------------
-- 5. INDICATORS OF COMPROMISE (IOCs)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.iocs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID REFERENCES public.cases(id) ON DELETE CASCADE,
    ioc_type TEXT NOT NULL, -- IP, DOMAIN, URL, HASH
    value TEXT NOT NULL,
    reputation_score INTEGER NOT NULL DEFAULT 0, -- 0 (clean) to 100 (malicious)
    is_malicious BOOLEAN NOT NULL DEFAULT FALSE,
    verdict TEXT DEFAULT 'UNKNOWN',
    enrichment_data JSONB DEFAULT '{}'::jsonb,
    source TEXT NOT NULL DEFAULT 'LOCAL_FORENSICS',
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- ----------------------------------------------------------------------------
-- 6. IP ADDRESSES & GEOLOCATION (Observed Infrastructure)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.ip_addresses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address TEXT NOT NULL UNIQUE,
    is_private BOOLEAN NOT NULL DEFAULT FALSE,
    country_name TEXT,
    country_code TEXT,
    city TEXT,
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    asn TEXT,
    isp TEXT,
    reputation_score INTEGER NOT NULL DEFAULT 0,
    last_checked TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- ----------------------------------------------------------------------------
-- 7. DOMAIN NAMES & LOOKALIKES
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_name TEXT NOT NULL UNIQUE,
    registrar TEXT,
    registered_at TIMESTAMPTZ,
    is_lookalike BOOLEAN NOT NULL DEFAULT FALSE,
    target_impersonated TEXT,
    reputation_score INTEGER NOT NULL DEFAULT 0,
    last_checked TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- ----------------------------------------------------------------------------
-- 8. SUSPICIOUS URLS
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.urls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    is_defanged BOOLEAN NOT NULL DEFAULT TRUE,
    threat_category TEXT DEFAULT 'SUSPICIOUS_LINK',
    virustotal_positives INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- ----------------------------------------------------------------------------
-- 9. EVIDENCE LEDGER (Append-Only Cryptographic Chain)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id TEXT NOT NULL UNIQUE, -- e.g. "ANV-EVD-2026-0001"
    case_id UUID NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    mime_type TEXT NOT NULL DEFAULT 'message/rfc822',
    sha256_hash TEXT NOT NULL,
    previous_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    ledger_index SERIAL UNIQUE,
    uploaded_by TEXT NOT NULL DEFAULT 'ANALYST',
    storage_path TEXT,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- ----------------------------------------------------------------------------
-- 10. ALERTS (Triage Queue for Web & Mobile)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'INFORMATIONAL',
    threat_type TEXT NOT NULL DEFAULT 'BEC',
    is_reviewed BOOLEAN NOT NULL DEFAULT FALSE,
    is_escalated BOOLEAN NOT NULL DEFAULT FALSE,
    fcm_message_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- ----------------------------------------------------------------------------
-- 11. AUDIT LOGS (Chain of Custody & Traceability)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_entity TEXT NOT NULL,
    target_id TEXT NOT NULL,
    details JSONB DEFAULT '{}'::jsonb,
    ip_address TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- ----------------------------------------------------------------------------
-- INDEXES FOR FORENSIC PERFORMANCE
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_cases_risk ON public.cases(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_cases_status ON public.cases(status);
CREATE INDEX IF NOT EXISTS idx_emails_sender ON public.emails(sender);
CREATE INDEX IF NOT EXISTS idx_emails_case ON public.emails(case_id);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON public.iocs(value);
CREATE INDEX IF NOT EXISTS idx_alerts_unreviewed ON public.alerts(is_reviewed, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_hash ON public.evidence(sha256_hash);

-- ----------------------------------------------------------------------------
-- ROW LEVEL SECURITY (RLS)
-- ----------------------------------------------------------------------------
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.emails ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- Allow authenticated users / service key full access
CREATE POLICY "Service Role Full Access Profiles" ON public.profiles FOR ALL USING (true);
CREATE POLICY "Service Role Full Access Cases" ON public.cases FOR ALL USING (true);
CREATE POLICY "Service Role Full Access Emails" ON public.emails FOR ALL USING (true);
CREATE POLICY "Service Role Full Access IOCs" ON public.iocs FOR ALL USING (true);
CREATE POLICY "Service Role Full Access Campaigns" ON public.campaigns FOR ALL USING (true);
CREATE POLICY "Service Role Full Access Evidence" ON public.evidence FOR ALL USING (true);
CREATE POLICY "Service Role Full Access Alerts" ON public.alerts FOR ALL USING (true);
CREATE POLICY "Service Role Full Access Audit" ON public.audit_logs FOR ALL USING (true);
