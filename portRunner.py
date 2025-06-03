#!/usr/bin/env python3
"""portRunner - Cross-platform multithreaded TCP port scanner.

It automatically selects the best scan engine that the OS and privileges
make available:

* **Raw connect engine** - Linux / macOS / Windows + Npcap when CAP_NET_RAW
  or Administrator is present.  Uses Scapy to craft SYN, observes SYN-ACK /
  RST, performs polite FIN, identical to a full three-way handshake.
* **Socket connect engine** - Works everywhere (plain user mode).  Uses the
  kernel's `connect_ex()` which internally does the same handshake and returns
  well-defined POSIX error codes.  Returns the same semantic states (OPEN /
  CLOSED / FILTERED).

Major features
--------------
* IPv4 CIDR expansion **and** hostname resolution (gaierror-safe).
* Strict port-range validation and early CLI rejection of illegal values.
* Thread pool with per-thread exclusive source-port slice ≥10000 to avoid
  collisions (raw mode only).
* Bounded producer queue (`--queue` flag) so multi-million scans can stream
  without exhausting RAM.
* Single dedicated **writer thread**→CSV (no file-handle races) and
  monotonic-time **token bucket**→rate-limit.
* SIGINT/KeyboardInterrupt checkpoint JSON + `--resume` recovery.
* Resource-limit guard (`RLIMIT_NOFILE` / Winsock practical cap) with
  friendly hints.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import logging.handlers
import os
import queue
import random
import resource
import signal
import socket
import sys
import threading
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Tuple

# Optional - Scapy only loaded when raw engine requested / available
try:
    from scapy.all import (
        IP,
        TCP,
        RandInt,
        L3RawSocket,
        send,
        sr1,
        conf,
    )
except ImportError:
    IP = TCP = RandInt = L3RawSocket = send = sr1 = conf = None  # type: ignore

###############################################################################
# CLI + validation                                                            #
###############################################################################

def port_token(token: str) -> Tuple[int, int]:
    """Return (lo, hi) inclusive for a port token."""
    if "-" in token:
        lo, hi = token.split("-", 1)
        lo, hi = int(lo), int(hi)
        if not (0 <= lo <= hi <= 65535):
            raise argparse.ArgumentTypeError(f"illegal port range: {token}")
        return lo, hi
    val = int(token)
    if not (0 <= val <= 65535):
        raise argparse.ArgumentTypeError(f"illegal port: {token}")
    return val, val


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="cross-platform TCP port scanner")
    p.add_argument("--ip", required=True, help="comma-separated IPv4/cidr/host list")
    p.add_argument("--port", required=True, help="comma-separated ports or ranges")
    p.add_argument("--worker", type=int, default=1, help="thread count (default 1)")
    p.add_argument("--timeout", type=float, default=2.0, help="probe timeout seconds")
    p.add_argument("--delay", type=int, default=0, help="per-probe delay ms")
    p.add_argument("--pps", type=int, default=0, help="global packets-per-second")
    p.add_argument("--queue", type=int, default=0, help="bounded queue size (0=auto)")
    p.add_argument("--dryrun", action="store_true", help="no packets, just walk list")
    p.add_argument("--resume", help="checkpoint json path")
    p.add_argument("--output", help="csv output path")
    return p.parse_args()

###############################################################################
# Host & port expansion                                                       #
###############################################################################

def expand_hosts(spec: str) -> List[str]:
    hosts: List[str] = []
    for token in (t.strip() for t in spec.split(",")):
        if not token:
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
            hosts.extend(str(h) for h in net.hosts())
            continue
        except ValueError:
            pass  # maybe hostname or single ip
        try:
            ipaddress.ip_address(token)
            hosts.append(token)
            continue
        except ValueError:
            pass
        # hostname → resolve
        try:
            infos = socket.getaddrinfo(token, None, proto=socket.IPPROTO_TCP)
            hosts.extend({info[4][0] for info in infos})
        except socket.gaierror:
            logging.warning("UNRESOLVED host %s - skipped", token)
    return hosts


def expand_ports(spec: str) -> List[int]:
    ports: List[int] = []
    for part in (p.strip() for p in spec.split(",")):
        if not part:
            continue
        lo, hi = port_token(part)
        ports.extend(range(lo, hi + 1))
    return ports

###############################################################################
# Source-port allocator (raw engine only)                                     #
###############################################################################
_port_slices: List[Tuple[int, int]] = []
_tls = threading.local()


def init_port_slices(workers: int):
    base, hi = 10000, 65535
    block = (hi - base + 1) // workers
    if block == 0:
        sys.exit("too many workers for source-port pool")
    for i in range(workers):
        start = base + i * block
        end = base + (i + 1) * block - 1 if i < workers - 1 else hi
        _port_slices.append((start, end))


def next_sport() -> int:
    rng = getattr(_tls, "rng", None)
    if rng is None:
        tid = int(threading.current_thread().name.split("-")[-1]) - 1
        _tls.slice = _port_slices[tid]
        _tls.rng = rng = random.Random()
    lo, hi = _tls.slice
    return rng.randint(lo, hi)

###############################################################################
# Rate limiter (monotonic)                                                    #
###############################################################################

def token_bucket(pps: int, stop: threading.Event):
    sem = threading.Semaphore(0)
    period = 1.0 / max(pps, 1)

    def refill():
        next_ts = time.monotonic()
        while not stop.is_set():
            now = time.monotonic()
            if now >= next_ts:
                sem.release()
                next_ts += period
            else:
                time.sleep(next_ts - now)

    threading.Thread(target=refill, name="bucket", daemon=True).start()
    return sem

###############################################################################
# Scan engines                                                                #
###############################################################################
@dataclass
class ScanResult:
    status: str
    latency_ms: float


def raw_connect_scan(dst_ip: str, dst_port: int, timeout: float) -> ScanResult:
    sport = next_sport()
    seq = RandInt()
    logging.info(f"Sending SYN to {dst_ip}:{dst_port} with sport {sport} and seq {seq}")
    syn = IP(dst=dst_ip) / TCP(sport=sport, dport=dst_port, flags="S", seq=seq)

    t0 = time.perf_counter()
    synack = sr1(syn, timeout=timeout, verbose=False)
    latency = (time.perf_counter() - t0) * 1000

    if not synack or not synack.haslayer(TCP):
        logging.info(f"No SYN-ACK received from {dst_ip}:{dst_port}")
        return ScanResult("FILTERED", latency)

    flags = synack[TCP].flags
    if flags & 0x12 == 0x12:  # SYN-ACK
        # SYN-ACK received, send ACK
        logging.info(f"Sending ACK to {dst_ip}:{dst_port} with sport {sport} and seq {seq + 1}")
        send(
            IP(dst=dst_ip)
            / TCP(sport=sport, dport=dst_port, seq=seq + 1, ack=synack[TCP].seq + 1, flags="A"),
            verbose=False,
        )
        # final ACK + polite close
        logging.info(f"Sending FIN to {dst_ip}:{dst_port} with sport {sport} and seq {seq + 1}")
        fin = IP(dst=dst_ip) / TCP(sport=sport, dport=dst_port, seq=seq + 1, ack=synack[TCP].seq + 1, flags="FA")
        finack = sr1(fin, timeout=1, verbose=False)
        if finack and finack[TCP].flags & 0x11 == 0x11:
            logging.info(f"FIN-ACK received from {dst_ip}:{dst_port}")
            logging.info(f"Sending ACK to {dst_ip}:{dst_port} with sport {sport} and seq {seq + 2}")
            send(IP(dst=dst_ip)/TCP(sport=sport, dport=dst_port,
                                    seq=seq+2, ack=finack[TCP].seq+1, flags="A"),
                                    verbose=False)
        return ScanResult("OPEN", latency)
    if flags & 0x14 == 0x14:
        logging.info(f"RST received from {dst_ip}:{dst_port}")
        return ScanResult("CLOSED", latency)
    logging.info(f"No response from {dst_ip}:{dst_port}")
    return ScanResult("FILTERED", latency)


def socket_connect_scan(dst_ip: str, dst_port: int, timeout: float) -> ScanResult:
    t0 = time.perf_counter()
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.settimeout(timeout)
        err = s.connect_ex((dst_ip, dst_port))
    latency = (time.perf_counter() - t0) * 1000
    if err == 0:
        logging.info(f"OPEN connection to {dst_ip}:{dst_port}")
        return ScanResult("OPEN", latency)
    if err in (socket.errno.ECONNREFUSED, 111, 10061):  # posix + win
        logging.info(f"CLOSED connection to {dst_ip}:{dst_port}")
        return ScanResult("CLOSED", latency)
    logging.info(f"FILTERED connection to {dst_ip}:{dst_port}")
    return ScanResult("FILTERED", latency)

###############################################################################
# Writer thread                                                               #
###############################################################################

def writer_thread(csv_path: Path, queue_: "queue.Queue[Tuple[str,str,int,str,float]]", stop: threading.Event):
    with csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "dst_ip", "dst_port", "status", "latency_ms"])
        while not stop.is_set() or not queue_.empty():
            try:
                row = queue_.get(timeout=0.2)
            except queue.Empty:
                continue
            w.writerow(row)
            queue_.task_done()

###############################################################################
# Checkpoint                                                                  #
###############################################################################

def save_checkpoint(path: Path, todo: Iterable[Tuple[str, int]], written: int):
    data = {
        "remaining": list(todo),
        "written_rows": written,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(data, indent=2))


def load_checkpoint(path: Path) -> List[Tuple[str, int]]:
    return json.loads(path.read_text())["remaining"]

###############################################################################
# Privilege / capability check                                                #
###############################################################################

def raw_capable() -> bool:
    if IP is None:
        return False
    if os.name == "nt":
        # scapy with npcap needs conf.use_pcap True
        return bool(getattr(conf, "use_pcap", False))
    if os.geteuid() == 0:
        return True
    # try cap_net_raw
    try:
        import subprocess

        return "cap_net_raw" in subprocess.check_output(["capsh", "--print"], text=True)
    except Exception:
        return False

###############################################################################
# Resource limit check                                                        #
###############################################################################

def check_fds(workers: int):
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    need = workers * 4  # conservative worst-case
    if need > soft:
        logging.warning(
            "FD limit (%d) lower than predicted need (%d). consider `ulimit -n %d`",
            soft,
            need,
            need,
        )

###############################################################################
# Worker                                                                      #
###############################################################################

def worker(
    q_in: "queue.Queue[Tuple[str,int]]",
    q_out: "queue.Queue[Tuple[str,str,int,str,float]]",
    stop: threading.Event,
    delay_s: float,
    timeout: float,
    dryrun: bool,
    engine,
    token
):
    while not stop.is_set():
        try:
            dst_ip, dst_port = q_in.get_nowait()
        except queue.Empty:
            return
        if token is not None:
            token.acquire()
        if dryrun:
            res = ScanResult("DRYRUN", 0.0)
        else:
            try:
                res = engine(dst_ip, dst_port, timeout)
            except Exception as exc:
                logging.exception("worker error %s:%d", dst_ip, dst_port)
                res = ScanResult("ERROR", 0.0)
        ts = datetime.utcnow().isoformat()
        q_out.put((ts, dst_ip, dst_port, res.status, round(res.latency_ms, 2)))
        q_in.task_done()
        if delay_s:
            time.sleep(delay_s)

###############################################################################
# Main                                                                        #
###############################################################################

def main():
    args = parse_args()
    # Remove duplicate basicConfig calls and set up root logger
    log_format = "[%(asctime)s][%(threadName)s] - %(message)s"
    logging.basicConfig(level=logging.INFO,
                        format=log_format,
                        datefmt="%Y-%m-%d %H:%M:%S")
    # File handler for rotating logs
    file_handler = logging.handlers.RotatingFileHandler(
        filename="portRunner.log", maxBytes=5 * 1024 * 1024, backupCount=3)
    file_handler.setFormatter(logging.Formatter(log_format, "%Y-%m-%d %H:%M:%S"))
    logging.getLogger().addHandler(file_handler)

    # Seed RNG for per-thread generators
    random.seed(os.getpid() ^ int(time.time()))

    # Build target list
    if args.resume:
        targets = load_checkpoint(Path(args.resume))
        logging.info("resuming with %d unfinished targets", len(targets))
    else:
        hosts = expand_hosts(args.ip)
        ports = expand_ports(args.port)
        targets = [(h, p) for h in hosts for p in ports]
        logging.info("generated %d (ip,port) tuples", len(targets))

    # Resource guard (posix)
    check_fds(args.worker)

    # In-memory queues
    qsize = args.queue or args.worker * 1024
    q_in: "queue.Queue[Tuple[str,int]]" = queue.Queue(maxsize=qsize)
    for t in targets:
        q_in.put(t)
    q_out: "queue.Queue[Tuple[str,str,int,str,float]]" = queue.Queue()

    # Stop flags
    stop_event = threading.Event()
    writer_stop = threading.Event()

    # Token bucket if requested
    token_sem = None
    if args.pps and not args.dryrun:
        token_sem = token_bucket(args.pps, stop_event)
        logging.info("global PPS capped at %d", args.pps)

    # Choose scan engine
    engine = socket_connect_scan
    if not args.dryrun and raw_capable():
        logging.info("using raw packet engine")
        engine = raw_connect_scan
        init_port_slices(args.worker)
        if IP is not None:
            conf.L3socket = L3RawSocket
    else:
        logging.info("using socket connect engine")

    # Output CSV path
    out_path = Path(args.output) if args.output else Path(
        f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")

    # Launch writer thread
    threading.Thread(target=writer_thread,
                     name="writer",
                     args=(out_path, q_out, writer_stop),
                     daemon=True).start()

    # Interrupt handler
    def handle_interrupt(signum=None, frame=None):
        logging.warning("SIGINT - writing checkpoint and shutting down …")
        remaining = []
        while not q_in.empty():
            try:
                remaining.append(q_in.get_nowait())
            except queue.Empty:
                break
        save_checkpoint(Path("checkpoint.json"), remaining)
        stop_event.set()
        writer_stop.set()

    if os.name != "nt":
        signal.signal(signal.SIGINT, handle_interrupt)

    # Spawn workers
    delay_s = args.delay / 1000.0
    workers: List[threading.Thread] = []
    for idx in range(args.worker):
        t = threading.Thread(target=worker,
                             name=f"runner-{idx+1}",
                             args=(q_in, q_out, stop_event, delay_s, args.timeout,
                                   args.dryrun, engine, token_sem),
                             daemon=True)
        t.start()
        workers.append(t)

    # Wait for all input processed
    try:
        q_in.join()
    except KeyboardInterrupt:
        handle_interrupt()

    # Signal shutdown and wait for workers to finish
    stop_event.set()
    for t in workers:
        t.join()

    # Wait until all CSV rows consumed then stop writer
    q_out.join()
    writer_stop.set()

    logging.info("scan complete - results saved to %s", out_path)


if __name__ == "__main__":
    main()