-- ============================================================================
-- ANVESH Migration: Campaign Intelligence Schema Alignment
-- Date: 2026-09-22
-- ============================================================================

-- 1. Align columns on public.campaigns
ALTER TABLE public.campaigns 
ADD COLUMN IF NOT EXISTS campaign_id VARCHAR(64),
ADD COLUMN IF NOT EXISTS status VARCHAR(32) DEFAULT 'ACTIVE',
ADD COLUMN IF NOT EXISTS confidence VARCHAR(32) DEFAULT 'HIGH',
ADD COLUMN IF NOT EXISTS case_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS email_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS ioc_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS first_observed_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS last_observed_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS evidence_summary JSONB,
ADD COLUMN IF NOT EXISTS explanation TEXT,
ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now(),
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();

-- 2. Adjust column constraints and defaults on public.campaigns
ALTER TABLE public.campaigns 
ALTER COLUMN severity SET DEFAULT 'HIGH',
ALTER COLUMN severity DROP NOT NULL,
ALTER COLUMN is_active SET DEFAULT TRUE,
ALTER COLUMN is_active DROP NOT NULL,
ALTER COLUMN threat_type SET DEFAULT 'BEC',
ALTER COLUMN confidence_score SET DEFAULT 75,
ALTER COLUMN first_seen SET DEFAULT now(),
ALTER COLUMN first_seen DROP NOT NULL,
ALTER COLUMN last_seen SET DEFAULT now(),
ALTER COLUMN last_seen DROP NOT NULL;

-- 3. Replace unique name index with regular index for dynamic cluster naming
DROP INDEX IF EXISTS public.ix_campaigns_name;
CREATE INDEX IF NOT EXISTS ix_campaigns_name ON public.campaigns (name);

-- 4. Create public.campaign_timeline table for chronological intelligence tracking
CREATE TABLE IF NOT EXISTS public.campaign_timeline (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id TEXT,
    case_id TEXT,
    event_type TEXT,
    timestamp TIMESTAMPTZ DEFAULT now(),
    title TEXT,
    description TEXT,
    signals JSONB
);

-- Enable RLS and permissions on campaign_timeline
ALTER TABLE public.campaign_timeline ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Service Role Full Access Campaign Timeline" ON public.campaign_timeline FOR ALL USING (true);
