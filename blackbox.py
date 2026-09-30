#!/usr/bin/env python3
"""
ServerBlackBox v1.0.0 — Ultra-Lightweight Server Flight Recorder

Continuously records comprehensive system diagnostics to a local JSONL file.
If the server crashes, review the blackbox file to diagnose the root cause.

Features:
  • CPU, Memory, Disk, Network, Processes, Services, Connections
  • Adaptive burst mode during high-load events
  • Ring-buffer file rotation with gzip archival
  • Security-hardened: sensitive data sanitization, restrictive permissions
  • Cross-platform: Linux & Windows
  • Zero network exposure, minimal resource footprint

Usage:
  python blackbox.py                      # Start recording (defaults)
  python blackbox.py --interval 15        # Custom interval
  python blackbox.py --oneshot            # Single snapshot → stdout
  python blackbox.py --check              # Verify installation

Dependency: psutil  (pip install psutil)
License: MIT
"""

__version__ = "1.0.0"

# ── stdlib imports (no third-party besides psutil) ───────────────────
import os
import sys
import re
import json
import time
import gzip
import signal
import socket
import hashlib
import logging
import platform
import argparse
import traceback
from datetime import datetime, timezone
from pathlib import Path
from contextlib import suppress

# ── single external dependency ───────────────────────────────────────
try:
    import psutil
except ImportError:
    sys.stderr.write(
        "FATAL: psutil is required.\n"
        "Install it with:  pip install psutil\n"
    )
    sys.exit(1)

# ── platform flags ───────────────────────────────────────────────────
IS_LINUX = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"

# Fix TOCTOU: set restrictive umask so ALL created files start with
# secure permissions, before any chmod() call.
if not IS_WINDOWS:
    os.umask(0o077)  # rw------- for files, rwx------ for dirs

DEFAULT_DIR = (
    Path("/var/lib/server-blackbox")
    if IS_LINUX
    else Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ServerBlackBox"
)

# ── compiled regex for sensitive data (built once) ───────────────────
# NOTE: patterns must be precise to avoid false-positive redaction of
# legitimate names (salt-minion, dbus --auth, codesigning, etc.).
_SENSITIVE = re.compile(
    r"(?i)(?:^|[_\-.])"
    r"(passw(?:or)?d|secret|(?:api|access|master|ssh)[_\-.]?key|"
    r"credential|private[_\-.]?key|auth[_\-.]?token|"
    r"session[_\-.]?secret|jwt[_\-.]?secret|bearer[_\-.]?token|"
    r"database[_\-.]?url|db[_\-.]?pass(?:word)?|"
    r"connection[_\-.]?string|client[_\-.]?secret|"
    r"aws_secret|azure_secret|gcp_secret|stripe_key|twilio_auth)"
    r"(?:$|[_\-.\s=])",
)

# ═════════════════════════════════════════════════════════════════════
#  Security Helpers
# ═════════════════════════════════════════════════════════════════════

def _sanitize_str(s, max_len=2048):
    """Truncate overly-long strings to bound memory usage."""
    if isinstance(s, str) and len(s) > max_len:
        return s[:max_len] + "…[truncated]"
    return s


def _sanitize_cmdline(args):
    """Redact values of sensitive flags in command-line arguments."""
    if not args:
        return []
    out, redact_next = [], False
    for arg in args:
        if redact_next:
            out.append("***")
            redact_next = False
            continue
        s = str(arg)
        if _SENSITIVE.search(s):
            if "=" in s:
                out.append(s.split("=", 1)[0] + "=***")
            else:
                out.append(s)
                redact_next = True
        else:
            out.append(_sanitize_str(s))
    return out


def _safe(fn, default=None):
    """Call *fn*; swallow any exception and return *default*."""
    try:
        return fn()
    except Exception:
        return default


# ═════════════════════════════════════════════════════════════════════
#  RingFile – size-bounded append-only JSONL with gzip rotation
# ═════════════════════════════════════════════════════════════════════

class RingFile:
    """Append JSON records to a JSONL file; rotate + gzip when full."""

    def __init__(self, path: Path, max_bytes: int, max_archives: int):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.max_archives = max_archives
        self._size = 0
        self._fd = None
        self._open()

    # ── internal ─────────────────────────────────────────────────────

    def _open(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not IS_WINDOWS:
            with suppress(OSError):
                os.chmod(str(self.path.parent), 0o700)
        # O_CLOEXEC: prevent leaking this fd to child processes
        # (subprocess calls in collectors would otherwise inherit it)
        if IS_LINUX:
            _opener = lambda p, flags: os.open(p, flags | os.O_CLOEXEC, 0o600)
            self._fd = open(self.path, "a", encoding="utf-8", buffering=1,
                            opener=_opener)
        else:
            self._fd = open(self.path, "a", encoding="utf-8", buffering=1)
        self._size = self.path.stat().st_size if self.path.exists() else 0
        if not IS_WINDOWS:
            with suppress(OSError):
                os.chmod(str(self.path), 0o600)

    def _rotate(self):
        self._fd.close()
        # shift older archives
        for i in range(self.max_archives, 0, -1):
            older = self.path.parent / f"{self.path.stem}.{i}.jsonl.gz"
            if i == self.max_archives and older.exists():
                older.unlink()
            newer = (
                self.path.parent / f"{self.path.stem}.{i - 1}.jsonl.gz"
                if i > 1
                else None
            )
            if newer and newer.exists():
                newer.rename(older)
        # compress current → .1.jsonl.gz
        archive = self.path.parent / f"{self.path.stem}.1.jsonl.gz"
        archived_ok = False
        try:
            with open(self.path, "rb") as src, gzip.open(
                archive, "wb", compresslevel=1
            ) as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
            if not IS_WINDOWS:
                with suppress(OSError):
                    os.chmod(str(archive), 0o600)
            archived_ok = True
        except Exception:
            # Gzip failed — try keeping uncompressed as last resort
            uncompressed = archive.with_suffix("")
            with suppress(OSError):
                if self.path.exists():
                    self.path.rename(uncompressed)
                    archived_ok = True
        # Only delete original if we successfully archived it
        if archived_ok:
            self.path.unlink(missing_ok=True)
        else:
            # Truncate in place if we couldn't archive at all (keep last 20%)
            try:
                lines = self.path.read_text(encoding="utf-8").strip().split("\n")
                keep = max(1, len(lines) // 5)
                self.path.write_text("\n".join(lines[-keep:]) + "\n", encoding="utf-8")
            except Exception:
                pass  # last resort: just keep writing, file grows beyond limit
        self._open()

    # ── public API ───────────────────────────────────────────────────

    def write_record(self, record: dict):
        """Serialize one record, append, fsync."""
        line = json.dumps(
            record, separators=(",", ":"), ensure_ascii=False, default=str
        ) + "\n"
        blen = len(line.encode("utf-8"))
        if self._size + blen > self.max_bytes:
            self._rotate()
        self._fd.write(line)
        self._fd.flush()
        with suppress(OSError):
            os.fsync(self._fd.fileno())
        self._size += blen

    def close(self):
        if self._fd:
            self._fd.flush()
            with suppress(OSError):
                os.fsync(self._fd.fileno())
            self._fd.close()
            self._fd = None


# ═════════════════════════════════════════════════════════════════════
#  Collectors – each returns a dict (or None to skip)
# ═════════════════════════════════════════════════════════════════════

def _collect_system():
    u = platform.uname()
    users = _safe(psutil.users, [])
    return {
        "os": f"{u.system} {u.release}",
        "kernel": u.version,
        "arch": u.machine,
        "hostname": socket.gethostname(),
        "fqdn": _safe(socket.getfqdn, ""),
        "boot": datetime.fromtimestamp(psutil.boot_time(), timezone.utc).isoformat(),
        "uptime_s": round(time.time() - psutil.boot_time()),
        "users": [
            {"name": x.name, "term": x.terminal or "", "host": x.host,
             "since": datetime.fromtimestamp(x.started, timezone.utc).isoformat()}
            for x in (users or [])
        ],
        "pid": os.getpid(),
    }


def _collect_cpu():
    d = {
        "pct": psutil.cpu_percent(interval=0),
        "per_core": psutil.cpu_percent(percpu=True, interval=0),
        "logical": psutil.cpu_count(),
        "physical": psutil.cpu_count(logical=False),
    }
    if hasattr(psutil, "getloadavg"):
        la = psutil.getloadavg()
        d["load"] = {"1": round(la[0], 2), "5": round(la[1], 2), "15": round(la[2], 2)}
    ct = psutil.cpu_times()
    d["times"] = {"user": ct.user, "sys": ct.system, "idle": ct.idle}
    for a in ("iowait", "steal", "irq", "softirq", "nice", "guest"):
        v = getattr(ct, a, None)
        if v is not None:
            d["times"][a] = v
    cs = _safe(psutil.cpu_stats)
    if cs:
        d["ctx"] = cs.ctx_switches
        d["intr"] = cs.interrupts
        d["soft_intr"] = cs.soft_interrupts
        if hasattr(cs, "syscalls"):
            d["syscalls"] = cs.syscalls
    freq = _safe(psutil.cpu_freq)
    if freq:
        d["freq"] = {"cur": round(freq.current), "min": round(freq.min), "max": round(freq.max)}
    return d


def _collect_memory():
    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()
    d = {
        "virt": {
            "total": vm.total, "avail": vm.available, "used": vm.used,
            "free": vm.free, "pct": vm.percent,
        },
        "swap": {
            "total": sw.total, "used": sw.used, "free": sw.free,
            "pct": sw.percent, "sin": sw.sin, "sout": sw.sout,
        },
    }
    for a in ("buffers", "cached", "shared", "slab", "active", "inactive"):
        v = getattr(vm, a, None)
        if v is not None:
            d["virt"][a] = v
    return d


def _collect_disk():
    parts = []
    for p in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(p.mountpoint)
            entry = {
                "dev": p.device, "mount": p.mountpoint, "fs": p.fstype,
                "total": u.total, "used": u.used, "free": u.free, "pct": u.percent,
            }
            # Inode usage (Linux only) — inode exhaustion is a silent killer
            if IS_LINUX:
                try:
                    st = os.statvfs(p.mountpoint)
                    if st.f_files > 0:
                        inode_used = st.f_files - st.f_ffree
                        entry["inodes_total"] = st.f_files
                        entry["inodes_used"] = inode_used
                        entry["inodes_pct"] = round(inode_used / st.f_files * 100, 1)
                except OSError:
                    pass
            parts.append(entry)
        except (PermissionError, OSError):
            parts.append({"dev": p.device, "mount": p.mountpoint, "err": "denied"})
    io = _safe(psutil.disk_io_counters)
    io_d = None
    if io:
        io_d = {
            "r_cnt": io.read_count, "w_cnt": io.write_count,
            "r_bytes": io.read_bytes, "w_bytes": io.write_bytes,
            "r_ms": io.read_time, "w_ms": io.write_time,
        }
        if hasattr(io, "busy_time"):
            io_d["busy_ms"] = io.busy_time
    # Per-disk IO (useful to identify which disk is bottleneck)
    per_disk = _safe(lambda: psutil.disk_io_counters(perdisk=True), {})
    per_d = None
    if per_disk:
        per_d = {}
        for dname, dc in per_disk.items():
            per_d[dname] = {
                "r_cnt": dc.read_count, "w_cnt": dc.write_count,
                "r_bytes": dc.read_bytes, "w_bytes": dc.write_bytes,
            }
    return {"parts": parts, "io": io_d, "per_disk": per_d}


def _collect_network():
    raw = _safe(lambda: psutil.net_io_counters(pernic=True), {})
    ifaces = {}
    for name, c in (raw or {}).items():
        ifaces[name] = {
            "tx_b": c.bytes_sent, "rx_b": c.bytes_recv,
            "tx_p": c.packets_sent, "rx_p": c.packets_recv,
            "err_in": c.errin, "err_out": c.errout,
            "drop_in": c.dropin, "drop_out": c.dropout,
        }
    addrs = _safe(psutil.net_if_addrs, {})
    addr_map = {}
    for name, al in (addrs or {}).items():
        addr_map[name] = [
            {"fam": str(a.family.name) if hasattr(a.family, 'name') else str(a.family), "addr": a.address}
            for a in al if a.address and not a.address.startswith("fe80")
        ]
    return {"ifaces": ifaces, "addrs": addr_map}


def _collect_connections():
    try:
        conns = psutil.net_connections(kind="all")
    except psutil.AccessDenied:
        # net_connections(kind="all") requires root/admin on most systems.
        # Return a clear indicator instead of silently returning empty.
        return {"n": 0, "by_st": {}, "listen": [], "estab": [],
                "err": "access_denied_need_root"}
    except Exception:
        conns = []
    if not conns:
        return {"n": 0, "by_st": {}, "listen": [], "estab": []}
    by_st = {}
    listen, estab = [], []
    for c in conns:
        st = c.status
        by_st[st] = by_st.get(st, 0) + 1
        if st == "LISTEN" and len(listen) < 80:
            listen.append({
                "la": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "pid": c.pid,
            })
        elif st == "ESTABLISHED" and len(estab) < 80:
            estab.append({
                "la": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "ra": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "pid": c.pid,
            })
    return {"n": len(conns), "by_st": by_st, "listen": listen, "estab": estab}


def _collect_processes(top_n=25):
    procs = []
    for p in psutil.process_iter(
        ["pid", "name", "status", "username", "cpu_percent",
         "memory_percent", "memory_info", "num_threads",
         "create_time", "nice", "cmdline"]
    ):
        try:
            i = p.info
            mi = i.get("memory_info")
            procs.append({
                "pid": i["pid"],
                "name": i.get("name", ""),
                "st": i.get("status", ""),
                "user": i.get("username", ""),
                "cpu": i.get("cpu_percent", 0) or 0,
                "mem": round(i.get("memory_percent", 0) or 0, 1),
                "rss": mi.rss if mi else 0,
                "vms": mi.vms if mi else 0,
                "thr": i.get("num_threads", 0),
                "nice": i.get("nice", 0),
                "cmd": _sanitize_cmdline(i.get("cmdline") or [])[:10],
                "since": (
                    datetime.fromtimestamp(i["create_time"], timezone.utc).isoformat()
                    if i.get("create_time") else ""
                ),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    procs.sort(key=lambda x: x["cpu"] + x["mem"], reverse=True)
    zombies = sum(1 for p in procs if p["st"] == "zombie")
    return {"total": len(procs), "zombies": zombies, "top": procs[:top_n]}


def _collect_services():
    if IS_WINDOWS:
        return _collect_win_services()
    if IS_LINUX:
        return _collect_systemd()
    return None


def _collect_systemd():
    import subprocess
    try:
        r = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all",
             "--no-pager", "--no-legend", "--plain"],
            capture_output=True, text=True, timeout=10,
        )
        svcs = []
        for line in r.stdout.strip().split("\n"):
            if not line.strip():  # guard against empty lines
                continue
            p = line.split(None, 4)
            if len(p) >= 4:
                svcs.append({"name": p[0], "load": p[1], "active": p[2], "sub": p[3]})
        # Also get failed units
        r2 = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=failed",
             "--no-pager", "--no-legend", "--plain"],
            capture_output=True, text=True, timeout=10,
        )
        failed = []
        for line in r2.stdout.strip().split("\n"):
            if not line.strip():
                continue
            p = line.split(None, 4)
            if len(p) >= 4:
                failed.append({"name": p[0], "load": p[1], "active": p[2], "sub": p[3]})
        return {"units": svcs, "failed": failed}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"err": "systemctl_unavailable"}
    except Exception as e:
        return {"err": str(e)}


def _collect_win_services():
    try:
        svcs = []
        for s in psutil.win_service_iter():
            try:
                info = s.as_dict()
                svcs.append({
                    "name": info.get("name", ""),
                    "display": info.get("display_name", ""),
                    "status": info.get("status", ""),
                    "start": info.get("start_type", ""),
                })
            except Exception:
                continue
        return {"services": svcs}
    except Exception as e:
        return {"err": str(e)}


def _collect_sensors():
    d = {}
    temps = _safe(psutil.sensors_temperatures, {})
    if temps:
        d["temp"] = {
            name: [{"label": t.label or "?", "cur": t.current,
                     "high": t.high, "crit": t.critical} for t in lst]
            for name, lst in temps.items()
        }
    fans = _safe(psutil.sensors_fans, {})
    if fans:
        d["fan"] = {
            name: [{"label": f.label or "?", "rpm": f.current} for f in lst]
            for name, lst in fans.items()
        }
    bat = _safe(psutil.sensors_battery)
    if bat:
        d["bat"] = {
            "pct": bat.percent, "plug": bat.power_plugged,
            "secs": bat.secsleft if bat.secsleft != psutil.POWER_TIME_UNLIMITED else -1,
        }
    return d or None


def _collect_fs():
    d = {}
    if IS_LINUX:
        try:
            with open("/proc/sys/fs/file-nr") as f:
                p = f.read().strip().split()
                d["fd_alloc"] = int(p[0])
                d["fd_free"] = int(p[1])
                d["fd_max"] = int(p[2])
        except Exception:
            pass
    return d or None


def _collect_kernel():
    if not IS_LINUX:
        return None
    import subprocess
    d = {}
    # Single dmesg call — parse errors AND OOM from one output.
    # Previous version called dmesg 3 separate times (wasteful).
    try:
        r = subprocess.run(
            ["dmesg", "--time-format=iso"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            all_lines = r.stdout.strip().split("\n")
            # Filter error/warning/critical lines
            error_keywords = ("error", "err ", "warn", "crit", "alert", "emerg",
                              "fail", "bug", "panic", "oops")
            err_lines = [l for l in all_lines
                         if any(kw in l.lower() for kw in error_keywords)]
            if err_lines:
                d["dmesg"] = err_lines[-30:]
            # OOM events from the same output
            oom_lines = [l for l in all_lines
                         if "oom" in l.lower() or "Out of memory" in l]
            if oom_lines:
                d["oom"] = oom_lines[-10:]
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        # Fallback: try without --time-format (older kernels)
        try:
            r = subprocess.run(
                ["dmesg"], capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                all_lines = r.stdout.strip().split("\n")
                error_keywords = ("error", "err ", "warn", "crit", "alert",
                                  "emerg", "fail", "bug", "panic", "oops")
                err_lines = [l for l in all_lines
                             if any(kw in l.lower() for kw in error_keywords)]
                if err_lines:
                    d["dmesg"] = err_lines[-30:]
                oom_lines = [l for l in all_lines
                             if "oom" in l.lower() or "Out of memory" in l]
                if oom_lines:
                    d["oom"] = oom_lines[-10:]
        except Exception:
            pass
    # /proc/vmstat highlights
    try:
        with open("/proc/vmstat") as f:
            want = {"pgfault", "pgmajfault", "oom_kill", "pswpin", "pswpout",
                    "pgpgin", "pgpgout", "nr_dirty", "nr_writeback"}
            vm = {}
            for line in f:
                k, _, v = line.partition(" ")
                if k in want:
                    vm[k] = int(v)
            if vm:
                d["vmstat"] = vm
    except Exception:
        pass
    # PSI – Pressure Stall Information
    for res in ("cpu", "memory", "io"):
        try:
            with open(f"/proc/pressure/{res}") as f:
                d.setdefault("psi", {})[res] = f.read().strip()
        except Exception:
            pass
    return d or None


# Firewall rules are static — no need to query every snapshot.
# We cache the result and only refresh every ~60 snapshots (~30min at 30s interval).
_fw_cache = {"val": None, "ttl": 0}


def _collect_security():
    if not IS_LINUX:
        return None
    import subprocess
    d = {}
    # SELinux
    try:
        r = subprocess.run(["getenforce"], capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            d["selinux"] = r.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # Failed SSH attempts (last 5 min)
    try:
        r = subprocess.run(
            ["journalctl", "-u", "sshd", "--since", "5 min ago",
             "--no-pager", "-q", "--output=short"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            fails = sum(1 for l in r.stdout.split("\n") if "Failed" in l or "Invalid" in l)
            d["ssh_fail_5m"] = fails
    except Exception:
        pass
    # Firewall rules — cached, checked infrequently.
    # Fix #5: iptables -L takes the netfilter lock and can stall under
    # high packet rates. Only query every ~30 minutes.
    global _fw_cache
    now = time.monotonic()
    if now >= _fw_cache["ttl"]:
        _fw_cache["ttl"] = now + 1800  # 30 min TTL
        fw_rules = 0
        # Try nftables first (modern distros: RHEL 8+, Debian 11+)
        try:
            r = subprocess.run(
                ["nft", "list", "ruleset"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                fw_rules = sum(1 for l in r.stdout.split("\n")
                               if l.strip().startswith(("rule", "chain")))
                _fw_cache["val"] = {"type": "nftables", "rules": fw_rules}
        except FileNotFoundError:
            # Fall back to iptables
            try:
                r = subprocess.run(
                    ["iptables", "-L", "-n", "--line-numbers"],
                    capture_output=True, text=True, timeout=5,
                )
                if r.returncode == 0:
                    fw_rules = sum(1 for l in r.stdout.split("\n")
                                   if l.strip() and not l.startswith("Chain")
                                   and not l.startswith("num"))
                    _fw_cache["val"] = {"type": "iptables", "rules": fw_rules}
            except Exception:
                _fw_cache["val"] = None
        except Exception:
            _fw_cache["val"] = None
    if _fw_cache["val"]:
        d["fw"] = _fw_cache["val"]
    return d or None


# ═════════════════════════════════════════════════════════════════════
#  ServerBlackBox – main engine
# ═════════════════════════════════════════════════════════════════════

class ServerBlackBox:
    """Ultra-lightweight flight recorder for servers."""

    def __init__(self, args):
        self.interval = args.interval
        self.burst_interval = args.burst_interval
        self.burst_dur = args.burst_duration
        self.top_n = args.top_processes
        self.cpu_th = args.cpu_threshold
        self.mem_th = args.mem_threshold
        self.disk_th = args.disk_threshold
        self.out_dir = Path(args.output_dir)
        self.running = False
        self._burst_until = 0.0
        self._prev_net = None
        self._prev_disk = None
        self._prev_ts = None
        self._seq = 0
        self._pid_fd = None  # kept open for flock

        # logging
        logging.basicConfig(
            level=getattr(logging, args.log_level.upper(), logging.WARNING),
            format="%(asctime)s [BB/%(levelname)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        self.log = logging.getLogger("blackbox")

        # ring-buffer file
        self.ring = RingFile(
            path=self.out_dir / "blackbox.jsonl",
            max_bytes=args.max_size_mb * 1024 * 1024,
            max_archives=args.max_archives,
        )

        # PID file with proper locking
        self.pid_path = self.out_dir / "blackbox.pid"
        self._acquire_pid_lock()

        # heartbeat file
        self.hb_path = self.out_dir / "heartbeat"

    # ── helpers ──────────────────────────────────────────────────────

    def _acquire_pid_lock(self):
        """Acquire exclusive lock on PID file. Prevents duplicate instances."""
        self.pid_path.parent.mkdir(parents=True, exist_ok=True)
        self._pid_fd = open(self.pid_path, "w")
        if IS_LINUX:
            import fcntl
            try:
                fcntl.flock(self._pid_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (IOError, OSError):
                self.log.error("Another instance is already running (PID file locked)")
                sys.exit(1)
        else:
            # Windows: check if PID exists
            try:
                if self.pid_path.stat().st_size > 0:
                    self._pid_fd.seek(0)
                    old_content = self._pid_fd.read().strip()
                    if old_content and psutil.pid_exists(int(old_content)):
                        self.log.warning("Another instance may be running (PID %s)", old_content)
            except (ValueError, OSError):
                pass
        self._pid_fd.seek(0)
        self._pid_fd.truncate()
        self._pid_fd.write(str(os.getpid()))
        self._pid_fd.flush()
        if not IS_WINDOWS:
            with suppress(OSError):
                os.chmod(str(self.pid_path), 0o600)

    def _write_hb(self):
        """Write heartbeat with fsync — must survive kernel crash."""
        try:
            fd = open(self.hb_path, "w")
            fd.write(datetime.now(timezone.utc).isoformat() + "\n" + str(os.getpid()))
            fd.flush()
            os.fsync(fd.fileno())
            fd.close()
        except OSError:
            pass

    def _notify_watchdog(self):
        """Send sd_notify WATCHDOG=1 to systemd if running as service."""
        # Fix #22: WatchdogSec is set in unit file, we must ping back
        notify_socket = os.environ.get("NOTIFY_SOCKET")
        if not notify_socket:
            return
        try:
            import socket as _sock
            sock = _sock.socket(_sock.AF_UNIX, _sock.SOCK_DGRAM)
            if notify_socket.startswith("@"):
                notify_socket = "\0" + notify_socket[1:]
            sock.sendto(b"WATCHDOG=1", notify_socket)
            sock.close()
        except Exception:
            pass

    def _rates(self, snapshot):
        """Compute network & disk throughput rates from the previous tick."""
        rates = {}
        now = time.monotonic()
        if self._prev_ts is not None:
            dt = now - self._prev_ts
            if dt > 0:
                nio = _safe(psutil.net_io_counters)
                if nio and self._prev_net:
                    rates["net"] = {
                        "tx_Bps": round((nio.bytes_sent - self._prev_net.bytes_sent) / dt),
                        "rx_Bps": round((nio.bytes_recv - self._prev_net.bytes_recv) / dt),
                    }
                self._prev_net = nio
                dio = _safe(psutil.disk_io_counters)
                if dio and self._prev_disk:
                    rates["disk"] = {
                        "r_Bps": round((dio.read_bytes - self._prev_disk.read_bytes) / dt),
                        "w_Bps": round((dio.write_bytes - self._prev_disk.write_bytes) / dt),
                    }
                self._prev_disk = dio
        else:
            self._prev_net = _safe(psutil.net_io_counters)
            self._prev_disk = _safe(psutil.disk_io_counters)
        self._prev_ts = now
        return rates or None

    def _burst_check(self, snap):
        cpu = snap.get("cpu", {}).get("pct", 0)
        mem = snap.get("mem", {}).get("virt", {}).get("pct", 0)
        reasons = []
        if cpu >= self.cpu_th:
            reasons.append(f"CPU={cpu}%")
        if mem >= self.mem_th:
            reasons.append(f"MEM={mem}%")
        for p in snap.get("disk", {}).get("parts", []):
            if p.get("pct", 0) >= self.disk_th:
                reasons.append(f"DISK[{p.get('mount')}]={p['pct']}%")
        if reasons:
            self._burst_until = time.time() + self.burst_dur
            self.log.warning("BURST MODE ← %s", ", ".join(reasons))

    # ── snapshot ─────────────────────────────────────────────────────

    def collect(self):
        t_start = time.monotonic()
        snap = {
            "v": __version__,
            "ts": datetime.now(timezone.utc).isoformat(),
            "seq": self._seq,
        }
        self._seq += 1

        collectors = [
            ("sys",  _collect_system),
            ("cpu",  _collect_cpu),
            ("mem",  _collect_memory),
            ("disk", _collect_disk),
            ("net",  _collect_network),
            ("conn", _collect_connections),
            ("proc", lambda: _collect_processes(self.top_n)),
            ("svc",  _collect_services),
            ("sens", _collect_sensors),
            ("fs",   _collect_fs),
            ("kern", _collect_kernel),
            ("sec",  _collect_security),
        ]
        for key, fn in collectors:
            try:
                val = fn()
                if val is not None:
                    snap[key] = val
            except Exception as exc:
                snap[key] = {"err": str(exc)}
                self.log.debug("Collector '%s' failed: %s", key, exc)

        rates = self._rates(snap)
        if rates:
            snap["rates"] = rates

        # How long the snapshot itself took (self-monitoring)
        snap["_dur_ms"] = round((time.monotonic() - t_start) * 1000)

        # integrity hash (computed over everything else)
        raw = json.dumps(snap, separators=(",", ":"), sort_keys=True, default=str)
        snap["_h"] = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return snap

    # ── main loop ────────────────────────────────────────────────────

    def run(self):
        self.running = True
        self.log.info(
            "ServerBlackBox v%s | interval=%ds burst=%ds dir=%s",
            __version__, self.interval, self.burst_interval, self.out_dir,
        )

        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self._on_signal)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, self._on_signal)

        # calibrate psutil CPU counters
        psutil.cpu_percent(interval=0)
        psutil.cpu_percent(percpu=True, interval=0)
        time.sleep(0.5)

        try:
            while self.running:
                t0 = time.monotonic()
                try:
                    snap = self.collect()
                    self.ring.write_record(snap)
                    self._write_hb()
                    self._burst_check(snap)
                    self._notify_watchdog()
                except Exception as exc:
                    self.log.error("Snapshot failed: %s", exc)
                    self.log.debug(traceback.format_exc())

                interval = (
                    self.burst_interval
                    if time.time() < self._burst_until
                    else self.interval
                )
                sleep = max(0.5, interval - (time.monotonic() - t0))
                deadline = time.monotonic() + sleep
                while self.running and time.monotonic() < deadline:
                    time.sleep(min(1.0, deadline - time.monotonic()))
        finally:
            self.ring.close()
            if self._pid_fd:
                self._pid_fd.close()
            with suppress(OSError):
                self.pid_path.unlink()
            self.log.info("ServerBlackBox stopped.")

    def _on_signal(self, signum, _frame):
        name = signal.Signals(signum).name
        self.log.info("Received %s — shutting down…", name)
        self.running = False


# ═════════════════════════════════════════════════════════════════════
#  One-shot helpers
# ═════════════════════════════════════════════════════════════════════

def _oneshot(top_n=25):
    """Single snapshot → pretty JSON on stdout."""
    psutil.cpu_percent(interval=0)
    time.sleep(0.5)

    # Build a minimal args-like namespace to reuse the class properly
    class _Args:
        interval = 30
        burst_interval = 5
        burst_duration = 300
        top_processes = top_n
        max_size_mb = 10
        max_archives = 0
        output_dir = str(Path(os.environ.get("TMPDIR", "/tmp")) / "blackbox-oneshot")
        cpu_threshold = 999
        mem_threshold = 999
        disk_threshold = 999
        log_level = "ERROR"

    bb = ServerBlackBox(_Args())
    snap = bb.collect()
    bb.ring.close()
    # Clean up temp dir
    with suppress(OSError):
        bb.pid_path.unlink()
    with suppress(OSError):
        (bb.out_dir / "blackbox.jsonl").unlink()
    with suppress(OSError):
        bb.out_dir.rmdir()
    print(json.dumps(snap, indent=2, default=str, ensure_ascii=False))


def _check(output_dir):
    """Print system summary and exit."""
    vm = psutil.virtual_memory()
    print(f"ServerBlackBox v{__version__}")
    print(f"  Python  : {sys.version.split()[0]}")
    print(f"  psutil  : {psutil.__version__}")
    print(f"  Platform: {platform.platform()}")
    print(f"  CPUs    : {psutil.cpu_count()} logical / {psutil.cpu_count(logical=False)} physical")
    print(f"  Memory  : {vm.total / (1024**3):.1f} GiB total, {vm.percent}% used")
    print(f"  Output  : {output_dir}")
    print("  Status  : OK ✓")


# ═════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        prog="blackbox",
        description="ServerBlackBox — ultra-lightweight server flight recorder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s                          Record with defaults\n"
            "  %(prog)s --interval 10            Every 10 s\n"
            "  %(prog)s --oneshot                Single snapshot to stdout\n"
            "  %(prog)s --check                  Verify install\n"
        ),
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--oneshot", action="store_true", help="One snapshot → stdout")
    ap.add_argument("--check", action="store_true", help="Verify and exit")
    ap.add_argument("--interval", type=int, default=30, help="Seconds between snapshots (default 30)")
    ap.add_argument("--burst-interval", type=int, default=5, help="Burst-mode interval (default 5)")
    ap.add_argument("--burst-duration", type=int, default=300, help="Burst-mode window in seconds (default 300)")
    ap.add_argument("--top-processes", type=int, default=25, help="Processes to keep per snapshot (default 25)")
    ap.add_argument("--max-size-mb", type=int, default=50, help="Max JSONL file size in MiB (default 50)")
    ap.add_argument("--max-archives", type=int, default=3, help="Rotated archives to keep (default 3)")
    ap.add_argument("--output-dir", default=str(DEFAULT_DIR), help=f"Output directory (default {DEFAULT_DIR})")
    ap.add_argument("--cpu-threshold", type=float, default=90.0, help="CPU%% for burst trigger (default 90)")
    ap.add_argument("--mem-threshold", type=float, default=90.0, help="Mem%% for burst trigger (default 90)")
    ap.add_argument("--disk-threshold", type=float, default=95.0, help="Disk%% for burst trigger (default 95)")
    ap.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    args = ap.parse_args()

    # input validation
    for name, val, lo in [
        ("interval", args.interval, 1),
        ("burst-interval", args.burst_interval, 1),
        ("max-size-mb", args.max_size_mb, 1),
        ("top-processes", args.top_processes, 1),
    ]:
        if val < lo:
            ap.error(f"--{name} must be >= {lo}")

    if args.oneshot:
        _oneshot(args.top_processes)
        return
    if args.check:
        _check(args.output_dir)
        return

    ServerBlackBox(args).run()


if __name__ == "__main__":
    main()
