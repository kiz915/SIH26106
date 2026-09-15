"""
Database Connection Manager with SQLAlchemy Async Engine.
Supports PostgreSQL (production) and SQLite (local development) via DATABASE_URL.
"""

import os
from typing import Optional, AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import text

# Base for declarative models (if we add ORM models later)
Base = declarative_base()

# Global engine and session factory
_engine = None
_async_session_factory = None


def get_database_url() -> str:
    """
    Get database URL from environment.
    Defaults to SQLite for local development.
    """
    return os.environ.get(
        "DATABASE_URL",
        "sqlite+aiosqlite:///./sih26106_forensics.db"
    )


def get_engine():
    """Get or create the async engine."""
    global _engine
    if _engine is None:
        db_url = get_database_url()
        
        # Engine configuration
        if db_url.startswith("postgresql"):
            # PostgreSQL with asyncpg
            _engine = create_async_engine(
                db_url,
                echo=False,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,
                pool_recycle=3600,
            )
        else:
            # SQLite with aiosqlite
            _engine = create_async_engine(
                db_url,
                echo=False,
                connect_args={"check_same_thread": False},
            )
    return _engine


def get_session_factory():
    """Get or create the async session factory."""
    global _async_session_factory
    if _async_session_factory is None:
        _async_session_factory = async_sessionmaker(
            get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _async_session_factory


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager for database sessions.
    Usage:
        async with get_db_session() as session:
            result = await session.execute(...)
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def init_db(db_path: Optional[str] = None) -> None:
    """Initialize the SQLite schema used by the current synchronous service layer."""
    init_db_sync(db_path)


async def close_db() -> None:
    """Close the database engine."""
    global _engine, _async_session_factory
    if _engine:
        await _engine.dispose()
        _engine = None
        _async_session_factory = None


# Backwards compatibility: synchronous connection for legacy code
def get_db_connection(db_path: Optional[str] = None):
    """
    Backwards compatible sync connection for SQLite only.
    Used by existing repository code that hasn't been migrated yet.
    """
    import sqlite3
    target_path = db_path or os.environ.get("SIH_DB_PATH", "./sih26106_forensics.db")
    conn = sqlite3.connect(target_path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    if target_path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def init_db_sync(db_path: Optional[str] = None) -> None:
    """Synchronous init for backwards compatibility."""
    import sqlite3
    target_path = db_path or os.environ.get("SIH_DB_PATH", "./sih26106_forensics.db")
    conn = sqlite3.connect(target_path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
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
