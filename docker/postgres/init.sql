-- PostgreSQL initialization script for SIH26106 Forensics
-- This runs as the postgres superuser during container initialization

-- Create database if not exists (handled by POSTGRES_DB env var)
-- Create user if not exists (handled by POSTGRES_USER env var)
-- Grant privileges

-- The main schema initialization is handled by migration 001_init.sql
-- This file exists for any superuser-level setup if needed

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Log initialization
DO $$
BEGIN
    RAISE NOTICE 'SIH26106 Forensics database initialized';
END $$;
