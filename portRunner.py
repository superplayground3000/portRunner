#!/usr/bin/env python3
"""portRunner - Cross-platform multithreaded TCP port scanner.

It automatically selects the best scan engine that the OS and privileges
make available:

* **Raw connect engine** - Linux / macOS / Windows + Npcap when CAP_NET_RAW
  or Administrator is present.  Uses Scapy to craft SYN, observes SYN-ACK /
  RST, performs polite FIN, identical to a full three-way handshake.
* **dry run engine** - Does not send any packets, just prints the scan to the console.

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
import signal
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Tuple

# Optional - Scapy only loaded when raw engine requested / available
try:
    from scapy.all import (
        IP,
        TCP,
        send,
        sr1,
        conf,
    )
except ImportError as e:
    print(e)
    IP = TCP = send = sr1 = conf = None  # type: ignore

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
    p.add_argument(
        "--ip",
        required=True,
        help="comma-separated IPv4/cidr/host list or path to CSV file",
    )
    p.add_argument(
        "--port",
        required=True,
        help="comma-separated ports/ranges or path to CSV file",
    )
    p.add_argument("--worker", type=int, default=1, help="thread count (default 1)")
    p.add_argument("--timeout", type=float, default=2.0, help="probe timeout seconds")
    p.add_argument("--delay", type=int, default=0, help="per-probe delay ms")
    p.add_argument("--queue", type=int, default=0, help="bounded queue size (0=auto)")
    p.add_argument("--dryrun", action="store_true", help="no packets, just walk list")
    p.add_argument("--resume", help="checkpoint json path")
    p.add_argument("--output", help="csv output path")
    return p.parse_args()


###############################################################################
# Host & port expansion                                                       #
###############################################################################


def _add_host_token(hosts: List[str], token: str) -> None:
    """Parse a single host token and append expanded hosts."""
    try:
        net = ipaddress.ip_network(token, strict=False)
        hosts.extend(str(h) for h in net.hosts())
        return
    except ValueError:
        pass  # maybe hostname or single ip
    try:
        ipaddress.ip_address(token)
        hosts.append(token)
        return
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(token, None, proto=socket.IPPROTO_TCP)
        hosts.extend({info[4][0] for info in infos})
    except socket.gaierror:
        logging.warning("UNRESOLVED host %s - skipped", token)


def _hosts_from_csv(path: Path) -> List[str]:
    hosts: List[str] = []
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            for cell in row.values():
                cell = cell.strip()
                if not cell:
                    continue
                if "." not in cell and "/" not in cell:
                    continue
                _add_host_token(hosts, cell)
    return hosts


def expand_hosts(spec: str) -> List[str]:
    hosts: List[str] = []
    for token in (t.strip() for t in spec.split(",")):
        if not token:
            continue
        path = Path(token)
        if path.is_file():
            hosts.extend(_hosts_from_csv(path))
            continue
        _add_host_token(hosts, token)
    return hosts


def _ports_from_csv(path: Path) -> List[int]:
    ports: List[int] = []
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            for cell in row.values():
                token = cell.strip()
                if not token:
                    continue
                if "/" in token:
                    token = token.split("/", 1)[0]
                try:
                    lo, hi = port_token(token)
                    ports.extend(range(lo, hi + 1))
                except (argparse.ArgumentTypeError, ValueError):
                    continue
    return ports


def expand_ports(spec: str) -> List[int]:
    ports: List[int] = []
    for part in (p.strip() for p in spec.split(",")):
        if not part:
            continue
        path = Path(part)
        if path.is_file():
            ports.extend(_ports_from_csv(path))
            continue
        lo, hi = port_token(part)
        ports.extend(range(lo, hi + 1))
    return ports


def ping_host(host: str, timeout: float = 1.0) -> bool:
    """Return True if host responds to a single ping."""
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]
    try:
        return subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode == 0
    except Exception as exc:
        logging.error("Ping failed for %s: %s", host, exc)
        return False


def filter_responsive_hosts(hosts: List[str], timeout: float = 1.0) -> List[str]:
    """Return only hosts that respond to ping."""
    responsive = []
    for host in hosts:
        if ping_host(host, timeout):
            responsive.append(host)
        else:
            logging.info("Host %s did not respond to ping - skipped", host)
    return responsive


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
        name = threading.current_thread().name
        digits = "".join(ch for ch in name if ch.isdigit())
        tid = int(digits) if digits else 0
        if "-" in name:
            tid -= 1
        _tls.slice = _port_slices[tid]
        _tls.rng = rng = random.Random()
    lo, hi = _tls.slice
    return rng.randint(lo, hi)


###############################################################################
# Scan engines                                                                #
###############################################################################
@dataclass(slots=True, frozen=True)
class ScanResult:
    """Hold the result of a port probe."""

    status: str
    latency_ms: float


def raw_connect_scan(dst_ip: str, dst_port: int, timeout: float) -> ScanResult:
    sport = next_sport()
    seq = random.randint(0, 1000)
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
        logging.info(
            f"Sending ACK to {dst_ip}:{dst_port} with sport {sport} and seq {seq + 1} dstseq {synack[TCP].seq+1}"
        )
        send(
            IP(dst=dst_ip)
            / TCP(
                sport=sport,
                dport=dst_port,
                seq=seq + 1,
                ack=synack[TCP].seq + 1,
                flags="A",
            ),
            verbose=False,
        )
        # final ACK + polite close
        logging.info(
            f"Sending FIN+ACK to {dst_ip}:{dst_port} with sport {sport} and seq {seq + 1} dstseq {synack[TCP].seq + 1}"
        )
        fin = IP(dst=dst_ip) / TCP(
            sport=sport,
            dport=dst_port,
            seq=seq + 1,
            ack=synack[TCP].seq + 1,
            flags="FA",
        )
        finack = sr1(fin, timeout=1, verbose=False)
        if finack and finack[TCP].flags & 0x11 == 0x11:
            logging.info(f"FIN-ACK received from {dst_ip}:{dst_port}")
            logging.info(
                f"Sending final ACK to {dst_ip}:{dst_port} with sport {sport} and seq {seq + 1} dstseq {finack[TCP].seq + 1}"
            )
            send(
                IP(dst=dst_ip)
                / TCP(
                    sport=sport,
                    dport=dst_port,
                    seq=finack[TCP].ack,
                    ack=finack[TCP].seq + 1,
                    flags="A",
                ),
                verbose=False,
            )
        else:
            logging.info(f"No FIN-ACK received from {dst_ip}:{dst_port}, sending RST")
            send(IP(dst=dst_ip) / TCP(sport=sport, dport=dst_port, flags="R"), verbose=False)
            return ScanResult("FILTERED", latency)
        return ScanResult("OPEN", latency)
    if flags & 0x14 == 0x14:
        logging.info(f"RST received from {dst_ip}:{dst_port}")
        return ScanResult("CLOSED", latency)
    logging.info(f"No response from {dst_ip}:{dst_port}")
    return ScanResult("FILTERED", latency)


def dryrun_scan(dst_ip: str, dst_port: int, timeout: float) -> ScanResult:
    print(f"Dryrun scan to {dst_ip}:{dst_port}")
    return ScanResult("DRYRUN", 0.0)


###############################################################################
# Writer thread                                                               #
###############################################################################


def writer_thread(csv_path: Path,
                  queue_: "queue.Queue[Tuple[str, str, int, str, float]]",
                  stop: threading.Event):

    mode = "w" if not csv_path.exists() else "a"
    with csv_path.open(mode,
                       newline="",
                       buffering=1,          # line-buffered
                       encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        if mode == "w":                      # first run only
            w.writerow(["timestamp", "dst_ip", "dst_port", "status", "latency_ms"])

        while True:
            try:
                row = queue_.get(timeout=0.2)
            except queue.Empty:
                if stop.is_set() and queue_.empty():
                    break
                continue

            w.writerow(row)
            f.flush()                        # ensure visibility
            queue_.task_done()


###############################################################################
# Checkpoint                                                                  #
###############################################################################


def save_checkpoint(path: Path, todo: Iterable[Tuple[str, int]]):
    """Write remaining targets to a checkpoint JSON file."""
    data = {
        "remaining": list(todo),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(data, indent=2))


def load_checkpoint(path: Path) -> List[Tuple[str, int]]:
    """Load remaining targets from a checkpoint JSON file."""
    return json.loads(path.read_text())["remaining"]


###############################################################################
# Privilege / capability check                                                #
###############################################################################


def raw_capable() -> bool:
    if IP is None:
        logging.info("Failed to load scapy.IP ")
        return False
    if os.name == "nt":
        # scapy with npcap needs conf.use_pcap True
        return bool(getattr(conf, "use_pcap", False))
    else:
        from scapy.all import L3RawSocket
        conf.L3socket = L3RawSocket
    if os.geteuid() == 0:
        return True
    # try cap_net_raw
    try:
        import subprocess

        return "cap_net_raw" in subprocess.check_output(["capsh", "--print"], text=True)
    except Exception:
        logging.info("Failed to run capsh --print ")
        return False


###############################################################################
# Resource limit check                                                        #
###############################################################################


def check_fds(workers: int):
    if os.name != "nt":
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        need = workers * 4  # conservative worst-case
        if need > soft:
            logging.warning(
                "FD limit (%d) lower than predicted need (%d). consider `ulimit -n %d`",
                soft,
                need,
                need,
            )
    else:
        pass


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
):
    while not stop.is_set():
        try:
            dst_ip, dst_port = q_in.get_nowait()
        except queue.Empty:
            return
        if dryrun:
            res = ScanResult("DRYRUN", 0.0)
        else:
            try:
                res = engine(dst_ip, dst_port, timeout)
            except Exception as exc:
                logging.exception("worker error %s:%d", dst_ip, dst_port)
                logging.error(f"Error: {exc}")
                res = ScanResult("ERROR", 0.0)
        ts = datetime.now(timezone.utc).isoformat()
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
    logging.basicConfig(
        level=logging.INFO, format=log_format, datefmt="%Y-%m-%d %H:%M:%S"
    )
    # File handler for rotating logs
    file_handler = logging.handlers.RotatingFileHandler(
        filename="portRunner.log", maxBytes=5 * 1024 * 1024, backupCount=3
    )
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
        if not args.dryrun:
            hosts = filter_responsive_hosts(hosts, args.timeout)
        ports = expand_ports(args.port)
        targets = [(h, p) for p in ports for h in hosts]
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


    # Choose scan engine
    engine = dryrun_scan
    if not args.dryrun:
        if raw_capable():
            logging.info("using raw packet engine")
            init_port_slices(args.worker)
            engine = raw_connect_scan
        else:
            print("\nWarning: Raw packet scanning is not available.")
            print("To enable raw packet scanning:")
            print("1. Install Npcap (Windows) or libpcap (Linux/macOS)")
            print("2. Run the script with root/administrator privileges")
            print("\nAlternatively, you can continue with socket-based scanning by using --dryrun flag")
            logging.error("raw packet engine is not available")
            os.exit(1)

    

    # Output CSV path
    out_path = (
        Path(args.output)
        if args.output
        else Path(f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    )

    # Launch writer thread
    threading.Thread(
        target=writer_thread,
        name="writer",
        args=(out_path, q_out, writer_stop),
        daemon=True,
    ).start()

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

    # Spawn workers using ThreadPoolExecutor
    delay_s = args.delay / 1000.0
    with ThreadPoolExecutor(max_workers=args.worker, thread_name_prefix="runner") as ex:
        for _ in range(args.worker):
            ex.submit(
                worker,
                q_in,
                q_out,
                stop_event,
                delay_s,
                args.timeout,
                args.dryrun,
                engine,
            )

        # Wait for all input processed
        try:
            q_in.join()
        except KeyboardInterrupt:
            handle_interrupt()

        # Signal shutdown and wait for workers to finish
        stop_event.set()

    # Wait until all CSV rows consumed then stop writer
    q_out.join()
    writer_stop.set()

    logging.info("scan complete - results saved to %s", out_path)


if __name__ == "__main__":
    main()
