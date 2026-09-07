"""
SQLite Database Connection Manager and Schema Initializer.
Uses standard library sqlite3 with foreign key enforcement and WAL mode.
"""

import sqlite3
import os
from typing import Optional

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "sih26106_forensics.db"
)


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Creates and configures an SQLite database connection.
    Enforces foreign keys and returns rows as dictionary-accessible sqlite3.Row objects.
    """
    target_path = db_path or os.environ.get("SIH_DB_PATH", DEFAULT_DB_PATH)
    conn = sqlite3.connect(target_path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    # WAL journal mode for concurrent read performance (ignored in memory DBs)
    if target_path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initializes the database schema for Cases, Evidence, and Analysis records.
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            # 1. Cases Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    classification TEXT NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at);")

            # 2. Evidence Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    collected_at TEXT NOT NULL,
                    storage_reference TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(sha256);")

            # 3. Analysis Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analysis (
                    case_id TEXT PRIMARY KEY,
                    analysis_json TEXT NOT NULL,
                    analysis_timestamp TEXT NOT NULL,
                    parser_version TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                );
            """)
    finally:
        conn.close()
