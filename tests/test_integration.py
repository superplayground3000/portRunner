import csv
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

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
        subprocess.run(["docker-compose", "-f", str(compose_file), "down"], check=False) # Use check=False for teardown robustness


@pytest.mark.skipif(not shutil.which("docker-compose"), reason="docker-compose not available")
def test_scan_resume_from_checkpoint(tmp_path):
    compose_file = Path(__file__).resolve().parent.parent / "docker-compose.yml"
    subprocess.run(["docker-compose", "-f", str(compose_file), "up", "-d"], check=True)
    try:
        time.sleep(2) # Wait for services to start
        output_csv_file = tmp_path / "scan_resumed.csv"
        checkpoint_file = tmp_path / "checkpoint.json"

        # 1. Simulate a previous scan that was interrupted by creating an initial CSV and a checkpoint file.
        # Initial CSV with one port already scanned
        with output_csv_file.open('w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "dst_ip", "dst_port", "status", "latency_ms"])
            # Simulate that 127.0.0.1:8000 was already scanned
            writer.writerow([datetime.now(timezone.utc).isoformat(), "127.0.0.1", 8000, "OPEN", "1.23"])

        # Create checkpoint file with remaining targets
        # Port 8001 should be OPEN (from web2 service), 9999 should be CLOSED/FILTERED
        remaining_targets = [["127.0.0.1", 8001], ["127.0.0.1", 9999]]
        checkpoint_data = {
            "remaining": remaining_targets,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with checkpoint_file.open('w') as f:
            json.dump(checkpoint_data, f)

        # 2. Run portRunner with --resume
        # Note: --ip and --port are required by argparse, but targets are loaded from checkpoint.
        cmd_resume = [
            sys.executable, str(Path(__file__).resolve().parent.parent / "portRunner.py"),
            "--ip", "127.0.0.1",
            "--port", "1", # Dummy port, actual targets from checkpoint
            "--worker", "1",
            "--timeout", "1",
            "--output", str(output_csv_file),
            "--resume", str(checkpoint_file)
        ]
        subprocess.run(cmd_resume, check=True)

        # 3. Verify the output CSV
        with output_csv_file.open('r', newline='') as f:
            rows = list(csv.DictReader(f))

        assert len(rows) == 3 # 1 initial, 2 resumed
        
        statuses = {}
        for row in rows:
            statuses[int(row["dst_port"])] = row["status"]
            assert row["dst_ip"] == "127.0.0.1"

        assert statuses[8000] == "OPEN"  # From initial dummy write
        assert statuses[8001] == "OPEN"  # Scanned via resume (web2 service)
        assert statuses[9999] in {"CLOSED", "FILTERED"}  # Scanned via resume

    finally:
        subprocess.run(["docker-compose", "-f", str(compose_file), "down"], check=False)


@pytest.mark.skipif(not shutil.which("docker-compose"), reason="docker-compose not available")
def test_scan_dry_run(tmp_path):
    compose_file = Path(__file__).resolve().parent.parent / "docker-compose.yml"
    # Docker services are not strictly needed for dry run, but starting them is harmless
    subprocess.run(["docker-compose", "-f", str(compose_file), "up", "-d"], check=True)
    try:
        time.sleep(2)
        output_csv_file = tmp_path / "dryrun_scan.csv"
        cmd = [
            sys.executable, str(Path(__file__).resolve().parent.parent / "portRunner.py"),
            "--ip", "127.0.0.1", "--port", "8000,9998",
            "--worker", "1", "--timeout", "1",
            "--dryrun",
            "--output", str(output_csv_file)
        ]
        subprocess.run(cmd, check=True)

        with output_csv_file.open('r', newline='') as f:
            rows = list(csv.DictReader(f))
        
        assert len(rows) == 2
        for row in rows:
            assert row["status"] == "DRYRUN"
            assert row["dst_ip"] == "127.0.0.1"
            assert row["dst_port"] in {"8000", "9998"}
            assert float(row["latency_ms"]) == 0.0
    finally:
        subprocess.run(["docker-compose", "-f", str(compose_file), "down"], check=False)
