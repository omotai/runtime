import os
import sqlite3
from pathlib import Path

DB_PATH = Path(os.environ.get("OMOTAI_DB", "runs/omotai.db"))


def init_db():
    os.makedirs(DB_PATH.parent, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        # API Keys table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                api_key TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Secrets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_name TEXT NOT NULL UNIQUE,
                secret_value TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Audit logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                agent_name TEXT,
                session_id TEXT,
                event TEXT,
                tool TEXT,
                url TEXT,
                verdict TEXT,
                rule TEXT,
                request_payload TEXT,
                response_payload TEXT
            )
        """)
        # Domains table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                origin TEXT NOT NULL UNIQUE,
                action TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Approvals table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                source TEXT NOT NULL DEFAULT 'agent',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # CREATE TABLE IF NOT EXISTS leaves an older table as it was: add what it lacks.
        # source: 'agent' = ask_human (model-written text), 'runtime' = confirmation the runtime
        # imposed (text built from facts).
        cols = {row[1] for row in cursor.execute("PRAGMA table_info(approvals)")}
        if "source" not in cols:
            cursor.execute("ALTER TABLE approvals ADD COLUMN source TEXT NOT NULL DEFAULT 'agent'")
        conn.commit()


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn
