import csv
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest


@pytest.mark.skipif(not shutil.which("docker-compose"), reason="docker-compose not available")
def test_scan_open_and_closed_ports(tmp_path):
    compose_file = Path(__file__).resolve().parent.parent / "docker-compose.yml"
    subprocess.run(["docker-compose", "-f", str(compose_file), "up", "-d"], check=True)
    try:
        time.sleep(2)
        out = tmp_path / "scan.csv"
        cmd = [sys.executable, str(Path(__file__).resolve().parent.parent / "portRunner.py"),
               "--ip", "127.0.0.1", "--port", "8000,9999", "--worker", "1", "--timeout", "1", "--output", str(out)]
        subprocess.run(cmd, check=True)
        rows = list(csv.DictReader(out.open()))
        status = {int(row["dst_port"]): row["status"] for row in rows}
        assert status[8000] == "OPEN"
        assert status[9999] in {"CLOSED", "FILTERED"}
    finally:
        subprocess.run(["docker-compose", "-f", str(compose_file), "down"], check=True)

