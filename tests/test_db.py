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
