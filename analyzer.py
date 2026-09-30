#!/usr/bin/env python3
"""
ServerBlackBox Analyzer — Post-Crash Diagnostic Report Generator

Reads blackbox.jsonl (and rotated archives) and produces a human-readable
diagnostic report: anomaly timeline, resource trends, top processes,
service failures, and actionable recommendations.

Usage:
  python analyzer.py /var/lib/server-blackbox
  python analyzer.py /var/lib/server-blackbox --last 60       # last 60 min
  python analyzer.py /var/lib/server-blackbox --json          # machine-readable
  python analyzer.py /var/lib/server-blackbox --output report.txt
"""

__version__ = "1.0.0"

import os
import sys
import json
import gzip
import argparse
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict

# ═════════════════════════════════════════════════════════════════════
#  Loader
# ═════════════════════════════════════════════════════════════════════

def load_snapshots(directory, last_minutes=None):
    """Load all snapshots from blackbox files, newest first."""
    d = Path(directory)
    if not d.exists():
        sys.stderr.write(f"ERROR: Directory not found: {d}\n")
        sys.exit(1)

    files = []
    # main file
    main = d / "blackbox.jsonl"
    if main.exists():
        files.append(("plain", main))
    # rotated archives
    for gz in sorted(d.glob("blackbox.*.jsonl.gz")):
        files.append(("gz", gz))
    # uncompressed rotated
    for f in sorted(d.glob("blackbox.*.jsonl")):
        if f != main:
            files.append(("plain", f))

    if not files:
        sys.stderr.write(f"ERROR: No blackbox files found in {d}\n")
        sys.exit(1)

    snapshots = []
    cutoff = None
    if last_minutes:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=last_minutes)

    for kind, path in files:
        try:
            if kind == "gz":
                with gzip.open(path, "rt", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            snap = json.loads(line)
                            if cutoff:
                                ts = _parse_ts(snap.get("ts", ""))
                                if ts and ts < cutoff:
                                    continue
                            snapshots.append(snap)
                        except json.JSONDecodeError:
                            continue
            else:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            snap = json.loads(line)
                            if cutoff:
                                ts = _parse_ts(snap.get("ts", ""))
                                if ts and ts < cutoff:
                                    continue
                            snapshots.append(snap)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            sys.stderr.write(f"WARN: Could not read {path}: {e}\n")

    # Sort by timestamp
    snapshots.sort(key=lambda s: s.get("ts", ""))
    return snapshots


def _parse_ts(ts_str):
    """Parse ISO timestamp string to datetime."""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def verify_integrity(snap):
    """Verify snapshot integrity hash without mutating the snapshot."""
    h = snap.get("_h")
    if h is None:
        return None  # no hash present
    # Reconstruct the dict without _h for hash computation (don't mutate input)
    snap_copy = {k: v for k, v in snap.items() if k != "_h"}
    raw = json.dumps(snap_copy, separators=(",", ":"), sort_keys=True, default=str)
    computed = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return computed == h


# ═════════════════════════════════════════════════════════════════════
#  Analysis Engine
# ═════════════════════════════════════════════════════════════════════

class Analyzer:
    def __init__(self, snapshots):
        self.snaps = snapshots
        self.anomalies = []
        self.warnings = []

    def analyze(self):
        """Run all analysis passes."""
        if not self.snaps:
            return
        self._check_cpu()
        self._check_memory()
        self._check_disk()
        self._check_network()
        self._check_processes()
        self._check_oom()
        self._check_services()
        self._check_connections()
        self._check_integrity()

    def _check_cpu(self):
        for s in self.snaps:
            cpu = s.get("cpu", {})
            pct = cpu.get("pct", 0)
            if pct >= 95:
                self.anomalies.append({
                    "ts": s["ts"], "level": "CRITICAL",
                    "component": "CPU",
                    "msg": f"CPU at {pct}%",
                })
            elif pct >= 85:
                self.warnings.append({
                    "ts": s["ts"], "level": "WARNING",
                    "component": "CPU",
                    "msg": f"CPU at {pct}%",
                })
            # iowait check
            iowait = cpu.get("times", {}).get("iowait")
            if iowait is not None:
                # High iowait as percentage of total time
                total = sum(cpu.get("times", {}).values())
                if total > 0:
                    iow_pct = (iowait / total) * 100
                    if iow_pct > 30:
                        self.anomalies.append({
                            "ts": s["ts"], "level": "CRITICAL",
                            "component": "CPU/IO",
                            "msg": f"IO wait at {iow_pct:.1f}% of total CPU time",
                        })
            # load average
            load = cpu.get("load", {})
            logical = cpu.get("logical", 1)
            if load.get("1", 0) > logical * 3:
                self.anomalies.append({
                    "ts": s["ts"], "level": "CRITICAL",
                    "component": "LOAD",
                    "msg": f"Load avg 1m={load['1']} (>{logical*3}, {logical} cores)",
                })
            elif load.get("1", 0) > logical * 2:
                self.warnings.append({
                    "ts": s["ts"], "level": "WARNING",
                    "component": "LOAD",
                    "msg": f"Load avg 1m={load['1']} (>{logical*2}, {logical} cores)",
                })

    def _check_memory(self):
        prev_pct = None
        for s in self.snaps:
            mem = s.get("mem", {}).get("virt", {})
            pct = mem.get("pct", 0)
            if pct >= 95:
                self.anomalies.append({
                    "ts": s["ts"], "level": "CRITICAL",
                    "component": "MEMORY",
                    "msg": f"Memory at {pct}% (avail={_fmt_bytes(mem.get('avail', 0))})",
                })
            elif pct >= 85:
                self.warnings.append({
                    "ts": s["ts"], "level": "WARNING",
                    "component": "MEMORY",
                    "msg": f"Memory at {pct}%",
                })
            # swap usage
            swap = s.get("mem", {}).get("swap", {})
            swap_pct = swap.get("pct", 0)
            if swap_pct >= 80:
                self.anomalies.append({
                    "ts": s["ts"], "level": "CRITICAL",
                    "component": "SWAP",
                    "msg": f"Swap at {swap_pct}% ({_fmt_bytes(swap.get('used', 0))} used)",
                })
            # Memory growth detection
            if prev_pct is not None and pct - prev_pct >= 10:
                self.warnings.append({
                    "ts": s["ts"], "level": "WARNING",
                    "component": "MEMORY",
                    "msg": f"Memory jumped {prev_pct}% → {pct}% between snapshots",
                })
            prev_pct = pct

    def _check_disk(self):
        for s in self.snaps:
            for p in s.get("disk", {}).get("parts", []):
                pct = p.get("pct", 0)
                mount = p.get("mount", "?")
                if pct >= 98:
                    self.anomalies.append({
                        "ts": s["ts"], "level": "CRITICAL",
                        "component": "DISK",
                        "msg": f"{mount} at {pct}% (free={_fmt_bytes(p.get('free', 0))})",
                    })
                elif pct >= 90:
                    self.warnings.append({
                        "ts": s["ts"], "level": "WARNING",
                        "component": "DISK",
                        "msg": f"{mount} at {pct}%",
                    })

    def _check_network(self):
        prev_errs = None
        for s in self.snaps:
            total_err = 0
            total_drop = 0
            for iface, data in s.get("net", {}).get("ifaces", {}).items():
                total_err += data.get("err_in", 0) + data.get("err_out", 0)
                total_drop += data.get("drop_in", 0) + data.get("drop_out", 0)
            if prev_errs is not None:
                new_errs = total_err - prev_errs[0]
                new_drops = total_drop - prev_errs[1]
                if new_errs > 100:
                    self.anomalies.append({
                        "ts": s["ts"], "level": "CRITICAL",
                        "component": "NETWORK",
                        "msg": f"{new_errs} new network errors since last snapshot",
                    })
                if new_drops > 100:
                    self.anomalies.append({
                        "ts": s["ts"], "level": "CRITICAL",
                        "component": "NETWORK",
                        "msg": f"{new_drops} new packet drops since last snapshot",
                    })
            prev_errs = (total_err, total_drop)

    def _check_processes(self):
        for s in self.snaps:
            proc = s.get("proc", {})
            zombies = proc.get("zombies", 0)
            if zombies >= 10:
                self.anomalies.append({
                    "ts": s["ts"], "level": "WARNING",
                    "component": "PROCESS",
                    "msg": f"{zombies} zombie processes detected",
                })
            # single process consuming >80% CPU
            for p in proc.get("top", []):
                if p.get("cpu", 0) > 80:
                    self.warnings.append({
                        "ts": s["ts"], "level": "WARNING",
                        "component": "PROCESS",
                        "msg": f"PID {p['pid']} ({p['name']}) using {p['cpu']}% CPU",
                    })
                if p.get("mem", 0) > 30:
                    self.warnings.append({
                        "ts": s["ts"], "level": "WARNING",
                        "component": "PROCESS",
                        "msg": f"PID {p['pid']} ({p['name']}) using {p['mem']}% memory ({_fmt_bytes(p.get('rss', 0))})",
                    })

    def _check_oom(self):
        for s in self.snaps:
            kern = s.get("kern", {})
            oom = kern.get("oom", [])
            if oom:
                self.anomalies.append({
                    "ts": s["ts"], "level": "CRITICAL",
                    "component": "OOM",
                    "msg": f"OOM killer active — {len(oom)} events: {oom[-1]}",
                })
            vmstat = kern.get("vmstat", {})
            if vmstat.get("oom_kill", 0) > 0:
                self.anomalies.append({
                    "ts": s["ts"], "level": "CRITICAL",
                    "component": "OOM",
                    "msg": f"oom_kill counter = {vmstat['oom_kill']}",
                })

    def _check_services(self):
        for s in self.snaps:
            svc = s.get("svc", {})
            failed = svc.get("failed", [])
            if failed:
                names = [f.get("name", "?") for f in failed[:5]]
                self.anomalies.append({
                    "ts": s["ts"], "level": "CRITICAL",
                    "component": "SERVICE",
                    "msg": f"{len(failed)} failed services: {', '.join(names)}",
                })

    def _check_connections(self):
        for s in self.snaps:
            conn = s.get("conn", {})
            tw = conn.get("by_st", {}).get("TIME_WAIT", 0)
            if tw > 5000:
                self.warnings.append({
                    "ts": s["ts"], "level": "WARNING",
                    "component": "NETWORK",
                    "msg": f"{tw} connections in TIME_WAIT",
                })
            cw = conn.get("by_st", {}).get("CLOSE_WAIT", 0)
            if cw > 500:
                self.anomalies.append({
                    "ts": s["ts"], "level": "CRITICAL",
                    "component": "NETWORK",
                    "msg": f"{cw} connections in CLOSE_WAIT (possible leak)",
                })
            total = conn.get("n", 0)
            if total > 10000:
                self.warnings.append({
                    "ts": s["ts"], "level": "WARNING",
                    "component": "NETWORK",
                    "msg": f"{total} total connections",
                })

    def _check_integrity(self):
        corrupt = 0
        for s in self.snaps:
            result = verify_integrity(s)
            if result is False:
                corrupt += 1
        if corrupt:
            self.warnings.append({
                "ts": "", "level": "WARNING",
                "component": "INTEGRITY",
                "msg": f"{corrupt} snapshots with invalid integrity hash (possible corruption/tampering)",
            })


# ═════════════════════════════════════════════════════════════════════
#  Report Generator
# ═════════════════════════════════════════════════════════════════════

def _fmt_bytes(b):
    """Human-readable byte size."""
    if b is None:
        return "?"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PiB"


def _fmt_ts(ts_str):
    """Shorten ISO timestamp for display."""
    if not ts_str:
        return "N/A"
    return ts_str.replace("T", " ").split("+")[0].split(".")[0]


def generate_report(snapshots, analyzer):
    """Generate a human-readable text report."""
    lines = []
    W = 72
    lines.append("═" * W)
    lines.append("  ServerBlackBox — Post-Crash Diagnostic Report")
    lines.append("═" * W)
    lines.append("")

    if not snapshots:
        lines.append("  No snapshots found.")
        return "\n".join(lines)

    first = snapshots[0]
    last = snapshots[-1]

    # ── Overview ─────────────────────────────────────────────────────
    lines.append("┌─ OVERVIEW " + "─" * (W - 12) + "┐")
    lines.append(f"│ Snapshots     : {len(snapshots)}")
    lines.append(f"│ Time range    : {_fmt_ts(first.get('ts'))} → {_fmt_ts(last.get('ts'))}")
    sys_info = last.get("sys", {})
    lines.append(f"│ Hostname      : {sys_info.get('hostname', '?')}")
    lines.append(f"│ OS            : {sys_info.get('os', '?')}")
    lines.append(f"│ Kernel        : {sys_info.get('kernel', '?')}")
    lines.append(f"│ Uptime        : {_fmt_duration(sys_info.get('uptime_s', 0))}")
    lines.append(f"│ BlackBox ver  : {last.get('v', '?')}")
    lines.append("└" + "─" * (W - 1) + "┘")
    lines.append("")

    # ── Last Snapshot Summary ────────────────────────────────────────
    lines.append("┌─ LAST SNAPSHOT (closest to crash) " + "─" * (W - 37) + "┐")
    cpu = last.get("cpu", {})
    mem = last.get("mem", {}).get("virt", {})
    swap = last.get("mem", {}).get("swap", {})
    lines.append(f"│ Timestamp     : {_fmt_ts(last.get('ts'))}")
    lines.append(f"│ CPU           : {cpu.get('pct', '?')}%")
    load = cpu.get("load", {})
    if load:
        lines.append(f"│ Load Average  : {load.get('1', '?')} / {load.get('5', '?')} / {load.get('15', '?')}")
    lines.append(f"│ Memory        : {mem.get('pct', '?')}% ({_fmt_bytes(mem.get('used', 0))} / {_fmt_bytes(mem.get('total', 0))})")
    lines.append(f"│ Swap          : {swap.get('pct', '?')}% ({_fmt_bytes(swap.get('used', 0))} / {_fmt_bytes(swap.get('total', 0))})")
    # Disk
    for p in last.get("disk", {}).get("parts", []):
        lines.append(f"│ Disk {p.get('mount', '?'):10s}: {p.get('pct', '?')}% (free={_fmt_bytes(p.get('free', 0))})")
    # Connections
    conn = last.get("conn", {})
    lines.append(f"│ Connections   : {conn.get('n', '?')} total")
    for st, cnt in sorted(conn.get("by_st", {}).items(), key=lambda x: -x[1]):
        lines.append(f"│   {st:20s}: {cnt}")
    # Processes
    proc = last.get("proc", {})
    lines.append(f"│ Processes     : {proc.get('total', '?')} total, {proc.get('zombies', 0)} zombie")
    lines.append("└" + "─" * (W - 1) + "┘")
    lines.append("")

    # ── Top Processes ────────────────────────────────────────────────
    lines.append("┌─ TOP PROCESSES (last snapshot) " + "─" * (W - 33) + "┐")
    lines.append(f"│ {'PID':>7s}  {'CPU%':>5s}  {'MEM%':>5s}  {'RSS':>10s}  {'THR':>4s}  NAME")
    lines.append("│ " + "-" * (W - 3))
    for p in proc.get("top", [])[:15]:
        lines.append(
            f"│ {p.get('pid', '?'):>7}  {p.get('cpu', 0):>5.1f}  {p.get('mem', 0):>5.1f}"
            f"  {_fmt_bytes(p.get('rss', 0)):>10s}  {p.get('thr', 0):>4}  {p.get('name', '?')}"
        )
    lines.append("└" + "─" * (W - 1) + "┘")
    lines.append("")

    # ── Anomaly Timeline ─────────────────────────────────────────────
    all_events = sorted(
        analyzer.anomalies + analyzer.warnings,
        key=lambda e: e.get("ts", ""),
    )
    # Deduplicate consecutive identical messages
    deduped = []
    prev_msg = None
    for ev in all_events:
        if ev["msg"] != prev_msg:
            deduped.append(ev)
            prev_msg = ev["msg"]

    if deduped:
        lines.append("┌─ ANOMALY TIMELINE " + "─" * (W - 20) + "┐")
        crit_count = sum(1 for e in deduped if e["level"] == "CRITICAL")
        warn_count = sum(1 for e in deduped if e["level"] == "WARNING")
        lines.append(f"│ Total: {len(deduped)} events ({crit_count} critical, {warn_count} warnings)")
        lines.append("│")
        for ev in deduped[-50:]:  # last 50 events
            marker = "🔴" if ev["level"] == "CRITICAL" else "🟡"
            lines.append(f"│ {marker} [{_fmt_ts(ev['ts'])}] [{ev['component']:8s}] {ev['msg']}")
        if len(deduped) > 50:
            lines.append(f"│ ... ({len(deduped) - 50} earlier events omitted)")
        lines.append("└" + "─" * (W - 1) + "┘")
        lines.append("")
    else:
        lines.append("┌─ ANOMALY TIMELINE " + "─" * (W - 20) + "┐")
        lines.append("│ ✅ No anomalies detected.")
        lines.append("└" + "─" * (W - 1) + "┘")
        lines.append("")

    # ── Resource Trends ──────────────────────────────────────────────
    lines.append("┌─ RESOURCE TRENDS " + "─" * (W - 19) + "┐")
    cpu_vals = [s.get("cpu", {}).get("pct", 0) for s in snapshots]
    mem_vals = [s.get("mem", {}).get("virt", {}).get("pct", 0) for s in snapshots]
    if cpu_vals:
        lines.append(f"│ CPU  — min: {min(cpu_vals):.0f}%  avg: {sum(cpu_vals)/len(cpu_vals):.0f}%  max: {max(cpu_vals):.0f}%")
    if mem_vals:
        lines.append(f"│ MEM  — min: {min(mem_vals):.0f}%  avg: {sum(mem_vals)/len(mem_vals):.0f}%  max: {max(mem_vals):.0f}%")
    # Show memory trend (growing?)
    if len(mem_vals) >= 5:
        first_5_avg = sum(mem_vals[:5]) / 5
        last_5_avg = sum(mem_vals[-5:]) / 5
        delta = last_5_avg - first_5_avg
        if delta > 5:
            lines.append(f"│ ⚠️  Memory trending UP (+{delta:.1f}% from start to end)")
        elif delta < -5:
            lines.append(f"│ ℹ️  Memory trending DOWN ({delta:.1f}% from start to end)")
        else:
            lines.append(f"│ ✅ Memory stable (Δ={delta:+.1f}%)")
    swap_vals = [s.get("mem", {}).get("swap", {}).get("pct", 0) for s in snapshots]
    if swap_vals and max(swap_vals) > 0:
        lines.append(f"│ SWAP — min: {min(swap_vals):.0f}%  avg: {sum(swap_vals)/len(swap_vals):.0f}%  max: {max(swap_vals):.0f}%")
    lines.append("└" + "─" * (W - 1) + "┘")
    lines.append("")

    # ── Listening Ports ──────────────────────────────────────────────
    listen = last.get("conn", {}).get("listen", [])
    if listen:
        lines.append("┌─ LISTENING PORTS (last snapshot) " + "─" * (W - 35) + "┐")
        for l in listen[:30]:
            lines.append(f"│  {l.get('la', '?'):30s}  PID={l.get('pid', '?')}")
        if len(listen) > 30:
            lines.append(f"│  ... and {len(listen) - 30} more")
        lines.append("└" + "─" * (W - 1) + "┘")
        lines.append("")

    # ── Failed Services ──────────────────────────────────────────────
    failed_svcs = last.get("svc", {}).get("failed", [])
    if failed_svcs:
        lines.append("┌─ FAILED SERVICES " + "─" * (W - 19) + "┐")
        for f in failed_svcs:
            lines.append(f"│  ❌ {f.get('name', '?'):40s} ({f.get('sub', '?')})")
        lines.append("└" + "─" * (W - 1) + "┘")
        lines.append("")

    # ── dmesg errors ─────────────────────────────────────────────────
    dmesg = last.get("kern", {}).get("dmesg", [])
    if dmesg:
        lines.append("┌─ KERNEL ERRORS (dmesg) " + "─" * (W - 25) + "┐")
        for d in dmesg[-15:]:
            lines.append(f"│  {d[:W-4]}")
        lines.append("└" + "─" * (W - 1) + "┘")
        lines.append("")

    # ── Security ─────────────────────────────────────────────────────
    sec = last.get("sec", {})
    if sec:
        lines.append("┌─ SECURITY " + "─" * (W - 12) + "┐")
        if "selinux" in sec:
            lines.append(f"│ SELinux       : {sec['selinux']}")
        if "ssh_fail_5m" in sec:
            lines.append(f"│ SSH failures  : {sec['ssh_fail_5m']} in last 5 min")
        if "fw_rules" in sec:
            lines.append(f"│ Firewall rules: {sec['fw_rules']}")
        lines.append("└" + "─" * (W - 1) + "┘")
        lines.append("")

    # ── Recommendations ──────────────────────────────────────────────
    recs = _generate_recommendations(snapshots, analyzer)
    if recs:
        lines.append("┌─ RECOMMENDATIONS " + "─" * (W - 19) + "┐")
        for i, r in enumerate(recs, 1):
            lines.append(f"│ {i}. {r}")
        lines.append("└" + "─" * (W - 1) + "┘")
        lines.append("")

    lines.append("═" * W)
    lines.append(f"  Report generated at {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"  {len(snapshots)} snapshots analyzed")
    lines.append("═" * W)

    return "\n".join(lines)


def _fmt_duration(seconds):
    if not seconds:
        return "?"
    d = int(seconds) // 86400
    h = (int(seconds) % 86400) // 3600
    m = (int(seconds) % 3600) // 60
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    parts.append(f"{m}m")
    return " ".join(parts)


def _generate_recommendations(snapshots, analyzer):
    """Generate actionable recommendations based on analysis."""
    recs = []
    last = snapshots[-1] if snapshots else {}

    # CPU
    cpu_vals = [s.get("cpu", {}).get("pct", 0) for s in snapshots]
    if cpu_vals and sum(cpu_vals) / len(cpu_vals) > 80:
        recs.append("HIGH CPU: Investigate top processes. Consider scaling horizontally or optimizing CPU-intensive workloads.")

    # Memory
    mem_vals = [s.get("mem", {}).get("virt", {}).get("pct", 0) for s in snapshots]
    if len(mem_vals) >= 5:
        first_avg = sum(mem_vals[:5]) / 5
        last_avg = sum(mem_vals[-5:]) / 5
        if last_avg - first_avg > 10:
            recs.append("MEMORY LEAK: Memory usage is steadily increasing. Check for leaking processes with growing RSS.")
    if mem_vals and max(mem_vals) > 90:
        recs.append("LOW MEMORY: Memory usage exceeded 90%. Add RAM or investigate high-memory processes.")

    # Swap
    swap_vals = [s.get("mem", {}).get("swap", {}).get("pct", 0) for s in snapshots]
    if swap_vals and max(swap_vals) > 50:
        recs.append("HIGH SWAP: Heavy swap usage indicates insufficient RAM. System performance will degrade.")

    # Disk
    for p in last.get("disk", {}).get("parts", []):
        if p.get("pct", 0) >= 90:
            recs.append(f"DISK FULL: {p.get('mount', '?')} at {p['pct']}%. Free space or expand the volume immediately.")

    # OOM
    has_oom = any(
        s.get("kern", {}).get("oom") or s.get("kern", {}).get("vmstat", {}).get("oom_kill", 0) > 0
        for s in snapshots
    )
    if has_oom:
        recs.append("OOM KILLER: Out-of-memory events detected. Increase RAM, add swap, or reduce workload.")

    # Zombies
    zombie_vals = [s.get("proc", {}).get("zombies", 0) for s in snapshots]
    if zombie_vals and max(zombie_vals) > 5:
        recs.append("ZOMBIE PROCESSES: Multiple zombie processes detected. Parent process is not reaping children correctly.")

    # Network errors
    crit_net = [a for a in analyzer.anomalies if a["component"] == "NETWORK"]
    if crit_net:
        recs.append("NETWORK ERRORS: Significant network errors/drops detected. Check NIC, cables, driver, or firewall rules.")

    # CLOSE_WAIT
    cw = last.get("conn", {}).get("by_st", {}).get("CLOSE_WAIT", 0)
    if cw > 100:
        recs.append(f"CONNECTION LEAK: {cw} CLOSE_WAIT connections. Application is not closing sockets properly.")

    # TIME_WAIT
    tw = last.get("conn", {}).get("by_st", {}).get("TIME_WAIT", 0)
    if tw > 5000:
        recs.append(f"TIME_WAIT FLOOD: {tw} TIME_WAIT connections. Consider tcp_tw_reuse or connection pooling.")

    # Failed services
    failed = last.get("svc", {}).get("failed", [])
    if failed:
        names = [f.get("name", "?") for f in failed[:3]]
        recs.append(f"FAILED SERVICES: {', '.join(names)}. Check with 'systemctl status <service>' and 'journalctl -u <service>'.")

    # FD exhaustion
    fs = last.get("fs", {})
    fd_alloc = fs.get("fd_alloc", 0)
    fd_max = fs.get("fd_max", 0)
    if fd_max > 0 and fd_alloc / fd_max > 0.8:
        recs.append(f"FD EXHAUSTION: {fd_alloc}/{fd_max} file descriptors allocated. Increase fs.file-max or find fd-leaking processes.")

    if not recs:
        recs.append("No critical issues detected in the recorded data. If the server crashed, the cause may be external (hardware, power, hypervisor).")

    return recs


# ═════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        prog="analyzer",
        description="ServerBlackBox Analyzer — post-crash diagnostic report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("directory", help="Path to ServerBlackBox data directory")
    ap.add_argument("--last", type=int, metavar="MINUTES",
                    help="Only analyze last N minutes of data")
    ap.add_argument("--json", action="store_true",
                    help="Output machine-readable JSON instead of text report")
    ap.add_argument("--output", "-o", metavar="FILE",
                    help="Write report to file instead of stdout")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    args = ap.parse_args()

    # Load data
    snapshots = load_snapshots(args.directory, last_minutes=args.last)
    if not snapshots:
        sys.stderr.write("No snapshots found in the specified time range.\n")
        sys.exit(1)

    # Analyze
    az = Analyzer(snapshots)
    az.analyze()

    if args.json:
        output = json.dumps({
            "snapshots_count": len(snapshots),
            "time_range": {
                "start": snapshots[0].get("ts"),
                "end": snapshots[-1].get("ts"),
            },
            "anomalies": az.anomalies,
            "warnings": az.warnings,
            "last_snapshot": snapshots[-1],
            "recommendations": _generate_recommendations(snapshots, az),
        }, indent=2, default=str, ensure_ascii=False)
    else:
        output = generate_report(snapshots, az)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
