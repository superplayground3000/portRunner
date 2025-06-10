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
        # Use the pytest tmp_path fixture (which is a Path object)
        # to create the output file path.
        output_csv_file = tmp_path / "scan.csv"

        cmd = [sys.executable, str(Path(__file__).resolve().parent.parent / "portRunner.py"),
               "--ip", "127.0.0.1", "--port", "8000,9999", "--worker", "1", "--timeout", "1", "--output", str(output_csv_file)]
        subprocess.run(cmd, check=True)
        with output_csv_file.open('r', newline='') as f:
            rows = list(csv.DictReader(f))
        status = {row["dst_port"]: row["status"] for row in rows}
        assert status[8000] == "OPEN"
        assert status[9999] in {"CLOSED", "FILTERED"}
    finally:
        subprocess.run(["docker-compose", "-f", str(compose_file), "down"], check=True)
