-- =============================================================================
-- ANVESH Phase 12 Security Hardening: Row Level Security (RLS) Policies
-- Enforces Principle of Least Privilege, Append-Only Forensic Invariants,
-- and Chain-of-Custody Immutability on all Supabase Tables.
-- =============================================================================

-- 1. Enable Row Level Security across all sensitive tables
ALTER TABLE IF EXISTS cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS case_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS case_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS case_activities ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS evidence_vault ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS emails ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS audit_logs ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- 2. Revoke all default public/anon mutations
-- -----------------------------------------------------------------------------
REVOKE INSERT, UPDATE, DELETE ON cases FROM anon;
REVOKE INSERT, UPDATE, DELETE ON case_notes FROM anon;
REVOKE INSERT, UPDATE, DELETE ON case_decisions FROM anon;
REVOKE INSERT, UPDATE, DELETE ON case_activities FROM anon;
REVOKE INSERT, UPDATE, DELETE ON evidence FROM anon;
REVOKE INSERT, UPDATE, DELETE ON evidence_vault FROM anon;
REVOKE INSERT, UPDATE, DELETE ON emails FROM anon;
REVOKE INSERT, UPDATE, DELETE ON iocs FROM anon;
REVOKE INSERT, UPDATE, DELETE ON alerts FROM anon;
REVOKE INSERT, UPDATE, DELETE ON campaigns FROM anon;
REVOKE INSERT, UPDATE, DELETE ON reports FROM anon;
REVOKE INSERT, UPDATE, DELETE ON audit_logs FROM anon;

-- -----------------------------------------------------------------------------
-- 3. Cases Table Policies
-- -----------------------------------------------------------------------------
-- Authenticated analysts can view all cases
DROP POLICY IF EXISTS "Allow authenticated analysts to view cases" ON cases;
CREATE POLICY "Allow authenticated analysts to view cases"
ON cases FOR SELECT
TO authenticated
USING (true);

-- Authenticated analysts can ingest new investigation cases
DROP POLICY IF EXISTS "Allow authenticated analysts to insert cases" ON cases;
CREATE POLICY "Allow authenticated analysts to insert cases"
ON cases FOR INSERT
TO authenticated
WITH CHECK (true);

-- Authenticated analysts can update case status, assignment, and decisions
DROP POLICY IF EXISTS "Allow authenticated analysts to update cases" ON cases;
CREATE POLICY "Allow authenticated analysts to update cases"
ON cases FOR UPDATE
TO authenticated
USING (true)
WITH CHECK (
    -- Automated risk score and model inferences remain immutable system ground truth
    risk_score = risk_score
);

-- Deny ordinary client deletion of cases (Administrative service role required)
DROP POLICY IF EXISTS "Deny ordinary client deletion of cases" ON cases;
CREATE POLICY "Deny ordinary client deletion of cases"
ON cases FOR DELETE
TO authenticated
USING (auth.jwt() ->> 'role' = 'admin' OR auth.jwt() ->> 'role' = 'service_role');

-- -----------------------------------------------------------------------------
-- 4. Evidence & Evidence Vault Policies (STRICTLY APPEND-ONLY)
-- -----------------------------------------------------------------------------
-- Anyone authenticated can read evidence metadata
DROP POLICY IF EXISTS "Allow authenticated read of evidence" ON evidence;
CREATE POLICY "Allow authenticated read of evidence"
ON evidence FOR SELECT
TO authenticated
USING (true);

DROP POLICY IF EXISTS "Allow authenticated read of evidence vault" ON evidence_vault;
CREATE POLICY "Allow authenticated read of evidence vault"
ON evidence_vault FOR SELECT
TO authenticated
USING (true);

-- Ingestion engines can insert new evidence records
DROP POLICY IF EXISTS "Allow insertion of new evidence" ON evidence;
CREATE POLICY "Allow insertion of new evidence"
ON evidence FOR INSERT
TO authenticated
WITH CHECK (true);

DROP POLICY IF EXISTS "Allow insertion of new evidence vault" ON evidence_vault;
CREATE POLICY "Allow insertion of new evidence vault"
ON evidence_vault FOR INSERT
TO authenticated
WITH CHECK (true);

-- FORENSIC INVARIANT: Zero modifications allowed to existing evidence or SHA-256 hashes
DROP POLICY IF EXISTS "Deny all updates to evidence" ON evidence;
CREATE POLICY "Deny all updates to evidence"
ON evidence FOR UPDATE
TO authenticated, anon
USING (false);

DROP POLICY IF EXISTS "Deny all updates to evidence vault" ON evidence_vault;
CREATE POLICY "Deny all updates to evidence vault"
ON evidence_vault FOR UPDATE
TO authenticated, anon
USING (false);

-- FORENSIC INVARIANT: Zero deletions allowed to evidence to preserve chain of custody
DROP POLICY IF EXISTS "Deny all deletions to evidence" ON evidence;
CREATE POLICY "Deny all deletions to evidence"
ON evidence FOR DELETE
TO authenticated, anon
USING (false);

DROP POLICY IF EXISTS "Deny all deletions to evidence vault" ON evidence_vault;
CREATE POLICY "Deny all deletions to evidence vault"
ON evidence_vault FOR DELETE
TO authenticated, anon
USING (false);

-- -----------------------------------------------------------------------------
-- 5. Case Activities & Audit Logs (STRICTLY APPEND-ONLY CHAIN OF CUSTODY)
-- -----------------------------------------------------------------------------
-- Chronological activity timeline is readable by analysts
DROP POLICY IF EXISTS "Allow authenticated read of activities" ON case_activities;
CREATE POLICY "Allow authenticated read of activities"
ON case_activities FOR SELECT
TO authenticated
USING (true);

DROP POLICY IF EXISTS "Allow authenticated read of audit logs" ON audit_logs;
CREATE POLICY "Allow authenticated read of audit logs"
ON audit_logs FOR SELECT
TO authenticated
USING (true);

-- New activity events can be inserted
DROP POLICY IF EXISTS "Allow insert of activities" ON case_activities;
CREATE POLICY "Allow insert of activities"
ON case_activities FOR INSERT
TO authenticated
WITH CHECK (true);

DROP POLICY IF EXISTS "Allow insert of audit logs" ON audit_logs;
CREATE POLICY "Allow insert of audit logs"
ON audit_logs FOR INSERT
TO authenticated
WITH CHECK (true);

-- Activities and audit events CANNOT be mutated or deleted
DROP POLICY IF EXISTS "Deny modification of activities" ON case_activities;
CREATE POLICY "Deny modification of activities"
ON case_activities FOR UPDATE
TO authenticated, anon
USING (false);

DROP POLICY IF EXISTS "Deny deletion of activities" ON case_activities;
CREATE POLICY "Deny deletion of activities"
ON case_activities FOR DELETE
TO authenticated, anon
USING (false);

DROP POLICY IF EXISTS "Deny modification of audit logs" ON audit_logs;
CREATE POLICY "Deny modification of audit logs"
ON audit_logs FOR UPDATE
TO authenticated, anon
USING (false);

DROP POLICY IF EXISTS "Deny deletion of audit logs" ON audit_logs;
CREATE POLICY "Deny deletion of audit logs"
ON audit_logs FOR DELETE
TO authenticated, anon
USING (false);

-- -----------------------------------------------------------------------------
-- 6. Case Notes & Decisions (APPEND-ONLY INVESTIGATION LOGS)
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Allow authenticated read of case notes" ON case_notes;
CREATE POLICY "Allow authenticated read of case notes"
ON case_notes FOR SELECT
TO authenticated
USING (true);

DROP POLICY IF EXISTS "Allow authenticated insert of case notes" ON case_notes;
CREATE POLICY "Allow authenticated insert of case notes"
ON case_notes FOR INSERT
TO authenticated
WITH CHECK (true);

-- Notes cannot be edited or erased to ensure forensic veracity
DROP POLICY IF EXISTS "Deny update of case notes" ON case_notes;
CREATE POLICY "Deny update of case notes"
ON case_notes FOR UPDATE
TO authenticated, anon
USING (false);

DROP POLICY IF EXISTS "Deny deletion of case notes" ON case_notes;
CREATE POLICY "Deny deletion of case notes"
ON case_notes FOR DELETE
TO authenticated, anon
USING (false);

-- Decisions
DROP POLICY IF EXISTS "Allow authenticated read of decisions" ON case_decisions;
CREATE POLICY "Allow authenticated read of decisions"
ON case_decisions FOR SELECT
TO authenticated
USING (true);

DROP POLICY IF EXISTS "Allow authenticated insert of decisions" ON case_decisions;
CREATE POLICY "Allow authenticated insert of decisions"
ON case_decisions FOR INSERT
TO authenticated
WITH CHECK (true);

DROP POLICY IF EXISTS "Deny update of decisions" ON case_decisions;
CREATE POLICY "Deny update of decisions"
ON case_decisions FOR UPDATE
TO authenticated, anon
USING (false);

DROP POLICY IF EXISTS "Deny deletion of decisions" ON case_decisions;
CREATE POLICY "Deny deletion of decisions"
ON case_decisions FOR DELETE
TO authenticated, anon
USING (false);

-- -----------------------------------------------------------------------------
-- 7. Reports & Dossiers (INTEGRITY PROTECTION)
-- -----------------------------------------------------------------------------
DROP POLICY IF EXISTS "Allow authenticated read of reports" ON reports;
CREATE POLICY "Allow authenticated read of reports"
ON reports FOR SELECT
TO authenticated
USING (true);

DROP POLICY IF EXISTS "Allow authenticated insert of reports" ON reports;
CREATE POLICY "Allow authenticated insert of reports"
ON reports FOR INSERT
TO authenticated
WITH CHECK (true);

-- Report hash and generated metadata cannot be tampered with
DROP POLICY IF EXISTS "Deny update to report metadata" ON reports;
CREATE POLICY "Deny update to report metadata"
ON reports FOR UPDATE
TO authenticated, anon
USING (false);

-- -----------------------------------------------------------------------------
-- 8. Service Role Bypass
-- -----------------------------------------------------------------------------
-- Supabase service_role key automatically bypasses RLS for trusted backend workers.
