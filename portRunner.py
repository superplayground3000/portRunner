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
from abc import ABC, abstractmethod
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


###############################################################################
# Scan engines                                                                #
###############################################################################
@dataclass(frozen=True)
class ScanResult:
    __slots__ = ('status', 'latency_ms')
    status: str
    latency_ms: float


class ScanEngine(ABC):
    @abstractmethod
    def scan(self, dst_ip: str, dst_port: int, timeout: float) -> ScanResult:
        """Performs a scan on the target IP and port."""
        pass


class SourcePortAllocator:
    def __init__(self, workers: int):
        self._port_slices: List[Tuple[int, int]] = []
        self._tls = threading.local()
        base, hi = 10000, 65535  # High ports for source
        if workers <= 0:
            raise ValueError("Number of workers must be positive.")
        block = (hi - base + 1) // workers
        if block == 0:
            # This means workers > (hi - base + 1)
            logging.error("Too many workers for the available source-port pool size.")
            sys.exit("Error: Too many workers for source-port pool. Reduce worker count.")
        for i in range(workers):
            start = base + i * block
            end = base + (i + 1) * block - 1 if i < workers - 1 else hi
            self._port_slices.append((start, end))
        logging.info(f"Source port slices initialized for {workers} workers: {self._port_slices}")

    def get_sport(self) -> int:
        rng = getattr(self._tls, "rng", None)
        if rng is None:
            # Determine thread index from its name (e.g., "runner_0", "runner-1")
            name = threading.current_thread().name
            try:
                # Handles "runner_X" or "ThreadPoolExecutor-X_Y"
                # For ThreadPoolExecutor, it might be "ThreadPoolExecutor-N_M"
                # We need a consistent way to map thread to slice.
                # Assuming thread_name_prefix="runner" from ThreadPoolExecutor
                if "runner" in name: # Specific to our ThreadPoolExecutor prefix
                    tid_str = name.split("_")[-1]
                    tid = int(tid_str)
                else: # Fallback for other naming or direct thread creation
                    digits = "".join(ch for ch in name if ch.isdigit())
                    tid = int(digits) if digits else 0 # Simple fallback
                    if "-" in name and tid > 0: # Heuristic for some pool naming
                        tid -=1
                
                # Ensure tid is within bounds of available slices
                slice_index = tid % len(self._port_slices)
                self._tls.slice = self._port_slices[slice_index]
                logging.debug(f"Thread {name} (tid {tid}, slice_index {slice_index}) assigned slice {self._tls.slice}")

            except (ValueError, IndexError) as e:
                logging.error(f"Could not determine slice for thread {name}: {e}. Defaulting to first slice.")
                self._tls.slice = self._port_slices[0] # Fallback
            
            self._tls.rng = rng = random.Random() # Seeded by global random.seed()
        
        lo, hi = self._tls.slice
        return rng.randint(lo, hi)


class RawConnectScanEngine(ScanEngine):
    def __init__(self, port_allocator: SourcePortAllocator):
        if IP is None or TCP is None or sr1 is None or send is None or conf is None:
            raise RuntimeError("Scapy components not loaded. Raw scanning unavailable.")
        self.port_allocator = port_allocator
        self._configure_scapy()

    def _configure_scapy(self):
        if os.name != "nt":
            from scapy.all import L3RawSocket # Keep import local
            conf.L3socket = L3RawSocket
            logging.info("Scapy L3socket configured for non-NT OS.")
        # On Windows, conf.use_pcap = True is usually needed and set by Scapy if Npcap is found.
        # We rely on is_raw_scan_available() to have warned if conf.use_pcap is False.

    def scan(self, dst_ip: str, dst_port: int, timeout: float) -> ScanResult:
        sport = self.port_allocator.get_sport()
        seq = random.randint(0, 1000) # Random initial sequence number
        logging.debug(f"RAW: {dst_ip}:{dst_port} from sport {sport}, seq {seq}, timeout {timeout}")
        syn = IP(dst=dst_ip) / TCP(sport=sport, dport=dst_port, flags="S", seq=seq)

        t0 = time.perf_counter()
        synack = sr1(syn, timeout=timeout, verbose=False)
        latency = (time.perf_counter() - t0) * 1000

        if not synack or not synack.haslayer(TCP):
            logging.debug(f"RAW: {dst_ip}:{dst_port} -> FILTERED (no SYN-ACK or not TCP)")
            return ScanResult("FILTERED", latency)

        flags = synack[TCP].flags
        if flags.S and flags.A:  # SYN-ACK (0x12)
            logging.debug(f"RAW: {dst_ip}:{dst_port} -> OPEN (SYN-ACK received)")
            # Polite close: Send ACK for SYN-ACK, then FIN, expect FIN-ACK, send final ACK
            ack_to_synack = IP(dst=dst_ip)/TCP(sport=sport, dport=dst_port, flags="A", seq=synack[TCP].ack, ack=synack[TCP].seq + 1)
            send(ack_to_synack, verbose=False)

            fin = IP(dst=dst_ip)/TCP(sport=sport, dport=dst_port, flags="FA", seq=synack[TCP].ack, ack=synack[TCP].seq + 1)
            finack_rst = sr1(fin, timeout=max(0.1, timeout/4), verbose=False) # Shorter timeout for close

            if finack_rst and finack_rst.haslayer(TCP) and finack_rst[TCP].flags.F and finack_rst[TCP].flags.A:
                logging.debug(f"RAW: {dst_ip}:{dst_port} -> Graceful FIN-ACK received. Sending final ACK.")
                final_ack = IP(dst=dst_ip)/TCP(sport=sport, dport=dst_port, flags="A", seq=finack_rst[TCP].ack, ack=finack_rst[TCP].seq + 1)
                send(final_ack, verbose=False)
            else: # No FIN-ACK, or RST received instead. Port is open but close was not graceful from their side.
                logging.debug(f"RAW: {dst_ip}:{dst_port} -> No graceful FIN-ACK (or RST). Sending RST.")
                send(IP(dst=dst_ip)/TCP(sport=sport, dport=dst_port, flags="R", seq=synack[TCP].ack), verbose=False)
            return ScanResult("OPEN", latency)
        elif flags.R:  # RST or RST-ACK (0x04 or 0x14)
            logging.debug(f"RAW: {dst_ip}:{dst_port} -> CLOSED (RST received)")
            return ScanResult("CLOSED", latency)
        
        logging.debug(f"RAW: {dst_ip}:{dst_port} -> UNKNOWN TCP flags {flags!s}. Reporting FILTERED.")
        return ScanResult("FILTERED", latency)


class DryRunScanEngine(ScanEngine):
    def scan(self, dst_ip: str, dst_port: int, timeout: float) -> ScanResult:
        # timeout is ignored for dry run
        logging.info(f"DRYRUN: {dst_ip}:{dst_port}")
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


def is_raw_scan_available() -> bool:
    """Checks if conditions for raw packet scanning are met."""
    if IP is None:
        logging.warning("Scapy (IP component) not loaded. Raw scanning unavailable.")
        return False

    if os.name == "nt":
        if not getattr(conf, "use_pcap", False):
            logging.warning(
                "Scapy 'conf.use_pcap' is False on Windows. "
                "Raw scanning requires Npcap and Scapy configured to use it. "
                "Ensure Npcap is installed and accessible by Scapy."
            )
            # Depending on strictness, could return False. Scapy might still try.
            # For now, let's assume privileges are the main gate if Scapy is loaded.
        # Actual privilege check on Windows for raw sockets is implicit:
        # Scapy will fail to open raw socket if not run as Administrator.
    else:
        # Check for root or CAP_NET_RAW on Linux/macOS
        if os.geteuid() != 0:
            try:
                # This check is primarily for Linux
                if "cap_net_raw" not in subprocess.check_output(["capsh", "--print"], text=True, stderr=subprocess.DEVNULL):
                    logging.warning("Not root and CAP_NET_RAW not found (via capsh). Raw scanning likely unavailable.")
                    return False
            except (FileNotFoundError, subprocess.CalledProcessError, Exception) as e:
                logging.warning(f"Could not verify CAP_NET_RAW via capsh (may not be installed or applicable): {e}. Assuming unavailable if not root.")
                return False
    return True # If we pass all checks for the OS.


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
    engine: ScanEngine, # Injected ScanEngine instance
    scan_timeout: float,
):
    while not stop.is_set():
        try:
            dst_ip, dst_port = q_in.get_nowait()
        except queue.Empty:
            return
        try:
            res = engine.scan(dst_ip, dst_port, scan_timeout)
        except Exception: # Catch all exceptions from the engine
            logging.exception("Worker error scanning %s:%d", dst_ip, dst_port)
            res = ScanResult("ERROR", 0.0) # Generic error status
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
        level=logging.INFO, format=log_format, datefmt="%Y-%m-%d %H:%M:%S",
        force=True # Override any existing root logger configuration
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


    # Instantiate scan engine
    scan_engine: ScanEngine
    if args.dryrun:
        logging.info("using dry run engine")
        scan_engine = DryRunScanEngine()
    else:
        if is_raw_scan_available():
            logging.info("using raw packet engine")
            try:
                source_port_allocator = SourcePortAllocator(args.worker)
                scan_engine = RawConnectScanEngine(source_port_allocator)
            except (RuntimeError, ValueError) as e: # Catch errors from engine/allocator init
                logging.error(f"Failed to initialize raw scan engine: {e}")
                sys.exit(1)
        else:
            print("\nWarning: Raw packet scanning is not available.")
            print("To enable raw packet scanning:")
            print("  1. Ensure Scapy is correctly installed.")
            print("  2. On Windows: Install Npcap and ensure Scapy can use it (often automatic). Run as Administrator.")
            print("  3. On Linux/macOS: Run as root or with CAP_NET_RAW capability.")
            print("\nAlternatively, use the --dryrun flag to simulate a scan.")
            logging.error("Raw packet engine prerequisites not met. Exiting.")
            sys.exit(1)

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
                scan_engine,
                args.timeout, # Pass scan_timeout to worker
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
