"""Unit tests for portRunner.py."""

import argparse
import csv
import dataclasses
import queue
import threading
from unittest import mock

import pytest

import portRunner as pr


def test_port_token_valid_single_and_range():
    """Verify port_token handles single values and ranges correctly."""
    assert pr.port_token("80") == (80, 80)
    assert pr.port_token("1-3") == (1, 3)


def test_port_token_invalid():
    """Ensure port_token raises argparse.ArgumentTypeError on bad input."""
    with pytest.raises(argparse.ArgumentTypeError):
        pr.port_token("70000")
    with pytest.raises(argparse.ArgumentTypeError):
        pr.port_token("10-5")


def test_expand_hosts_with_csv_and_hostname(tmp_path):
    """Expand hosts from CSV and hostname, mocking DNS resolution."""
    csv_file = tmp_path / "hosts.csv"
    csv_file.write_text("name\nexample.com")
    with mock.patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("1.1.1.1", 0))]):
        hosts = pr.expand_hosts(f"{csv_file},192.168.0.0/30")
    assert set(hosts) == {"1.1.1.1", "192.168.0.1", "192.168.0.2"}


def test_expand_ports_with_csv(tmp_path):
    """Expand ports from range and CSV content."""
    csv_file = tmp_path / "ports.csv"
    csv_file.write_text("p\n1-2")
    ports = pr.expand_ports(f"{csv_file},5")
    assert ports == [1, 2, 5]


def test_filter_responsive_hosts(monkeypatch):
    """filter_responsive_hosts should return only hosts that ping successfully."""
    responses = {"a": True, "b": False}
    monkeypatch.setattr(pr, "ping_host", lambda h, timeout=1.0: responses[h])
    result = pr.filter_responsive_hosts(["a", "b"], timeout=0.1)
    assert result == ["a"]


def test_init_port_slices_and_next_sport():
    """Verify sports are allocated within thread specific slices."""
    pr._port_slices.clear()
    pr.init_port_slices(2)
    results = []

    def worker():
        results.append(pr.next_sport())

    # Simulate ThreadPoolExecutor naming convention
    t1 = threading.Thread(target=worker, name="runner_0")
    t2 = threading.Thread(target=worker, name="runner_1")
    t1.start(); t2.start(); t1.join(); t2.join()

    slice1, slice2 = pr._port_slices
    results.sort()
    assert slice1[0] <= results[0] <= slice1[1]
    assert slice2[0] <= results[1] <= slice2[1]


def test_writer_thread(tmp_path):
    """writer_thread should flush queued rows into a CSV file."""
    out = tmp_path / "out.csv"
    q = queue.Queue()
    stop = threading.Event()
    th = threading.Thread(target=pr.writer_thread, args=(out, q, stop))
    th.start()
    q.put(("t", "ip", 1, "OK", 0.1))
    q.join()
    stop.set()
    th.join(timeout=1)
    rows = list(csv.reader(out.open()))
    assert rows[0] == ["timestamp", "dst_ip", "dst_port", "status", "latency_ms"]
    assert rows[1] == ["t", "ip", "1", "OK", "0.1"]


def test_checkpoint(tmp_path):
    """save_checkpoint and load_checkpoint round trip."""
    path = tmp_path / "c.json"
    pr.save_checkpoint(path, [("a", 1), ("b", 2)])
    loaded = pr.load_checkpoint(path)
    assert loaded == [["a", 1], ["b", 2]]


def test_scanresult_frozen_and_slots():
    """ScanResult should be immutable and use slots."""
    res = pr.ScanResult("OPEN", 1.0)
    assert hasattr(pr.ScanResult, "__slots__")
    with pytest.raises(dataclasses.FrozenInstanceError):
        res.status = "CLOSED"


def test_ping_host_calls_subprocess(monkeypatch):
    """ping_host should invoke subprocess.run with expected command."""
    calls = []

    def fake_run(cmd, stdout=None, stderr=None):
        calls.append(cmd)
        class R:
            returncode = 0
        return R()

    monkeypatch.setattr(pr.subprocess, "run", fake_run)
    assert pr.ping_host("1.2.3.4", timeout=0.5) is True
    assert calls, "subprocess.run was not called"

