-- Migration 001: Initial schema for SIH26106 Forensics
-- Run this after database creation

-- Cases table
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    original_filename TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    risk_score INTEGER NOT NULL DEFAULT 0,
    classification TEXT NOT NULL DEFAULT 'UNKNOWN'
);

CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_classification ON cases(classification);

-- Evidence table
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    collected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    storage_reference TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(sha256);
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_sha256 ON evidence(sha256);

-- Analysis table with JSONB for flexible analysis storage
CREATE TABLE IF NOT EXISTS analysis (
    case_id TEXT PRIMARY KEY,
    analysis_json JSONB NOT NULL,
    analysis_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    parser_version TEXT NOT NULL DEFAULT '1.0.0',
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_analysis_jsonb ON analysis USING GIN (analysis_json);
CREATE INDEX IF NOT EXISTS idx_analysis_timestamp ON analysis(analysis_timestamp DESC);

-- Custody log table for chain of custody tracking
CREATE TABLE IF NOT EXISTS custody_log (
    log_id BIGSERIAL PRIMARY KEY,
    case_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    details JSONB,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_custody_log_case_id ON custody_log(case_id);
CREATE INDEX IF NOT EXISTS idx_custody_log_timestamp ON custody_log(timestamp DESC);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for cases table
DROP TRIGGER IF EXISTS update_cases_updated_at ON cases;
CREATE TRIGGER update_cases_updated_at
    BEFORE UPDATE ON cases
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Migration version tracking
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    description TEXT
);

INSERT INTO schema_migrations (version, description) 
VALUES ('001', 'Initial schema for SIH26106 Forensics')
ON CONFLICT (version) DO NOTHING;
