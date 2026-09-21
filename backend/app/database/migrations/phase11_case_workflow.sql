-- ==============================================================================
-- PHASE 11: ANVESH CASE MANAGEMENT & ANALYST WORKFLOW MIGRATION
-- ==============================================================================

-- 1. Extend cases table with analyst workflow and decision fields
ALTER TABLE cases ADD COLUMN IF NOT EXISTS analyst_decision VARCHAR(32);
ALTER TABLE cases ADD COLUMN IF NOT EXISTS analyst_decision_reason TEXT;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS analyst_decision_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS analyst_decision_by VARCHAR(128);
ALTER TABLE cases ADD COLUMN IF NOT EXISTS escalation_reason TEXT;

-- 2. Create case_notes table (append-only investigation notes)
CREATE TABLE IF NOT EXISTS case_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id VARCHAR(64) NOT NULL,
    author_id VARCHAR(128) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_case_notes_case_id ON case_notes(case_id);
CREATE INDEX IF NOT EXISTS idx_case_notes_created_at ON case_notes(created_at);

-- 3. Create case_decisions history table
CREATE TABLE IF NOT EXISTS case_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id VARCHAR(64) NOT NULL,
    decision VARCHAR(32) NOT NULL,
    reason TEXT NOT NULL,
    analyst_id VARCHAR(128) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_case_decisions_case_id ON case_decisions(case_id);

-- 4. Create case_activities table (unified chronological timeline)
CREATE TABLE IF NOT EXISTS case_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    actor VARCHAR(128) NOT NULL,
    actor_type VARCHAR(16) NOT NULL DEFAULT 'ANALYST', -- 'SYSTEM' or 'ANALYST'
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_case_activities_case_id ON case_activities(case_id);
CREATE INDEX IF NOT EXISTS idx_case_activities_timestamp ON case_activities(timestamp);
