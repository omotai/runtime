import os
import subprocess
import sys


def test_omotai_db_env_moves_the_database(tmp_path):
    target = tmp_path / "sub" / "run.db"
    code = "from omotai.dashboard.db import init_db; init_db()"
    env = {**os.environ, "OMOTAI_DB": str(target)}
    subprocess.run([sys.executable, "-c", code], cwd=tmp_path, env=env, check=True)  # noqa: S603
    assert target.exists()
    assert not (tmp_path / "runs").exists()  # the default location is not touched


def test_init_db_adds_source_to_an_older_approvals_table(monkeypatch, tmp_path):
    import sqlite3

    from omotai.dashboard import db

    old = tmp_path / "old.db"
    with sqlite3.connect(old) as conn:
        conn.execute(
            "CREATE TABLE approvals (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " session_id TEXT NOT NULL, reason TEXT NOT NULL,"
            " status TEXT NOT NULL DEFAULT 'pending',"
            " created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        conn.execute("INSERT INTO approvals (session_id, reason) VALUES ('s', 'older row')")
    monkeypatch.setattr(db, "DB_PATH", old)
    db.init_db()
    db.init_db()  # idempotent
    with sqlite3.connect(old) as conn:
        assert conn.execute("SELECT source FROM approvals").fetchall() == [("agent",)]
