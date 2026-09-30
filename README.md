# 🛩️ ServerBlackBox

**Ultra-lightweight server flight recorder for post-crash forensics.**

Just like an airplane's black box, ServerBlackBox continuously records comprehensive system diagnostics to a local file. When your server crashes, you can review the blackbox to diagnose exactly what happened — from CPU spikes to memory leaks to disk exhaustion.

---

## ✨ Features

| Feature | Description |
|---|---|
| **Comprehensive** | CPU, Memory, Disk, Network, Processes, Services, Connections, Kernel, Sensors, Security |
| **Ultra-Lightweight** | Single file, single dependency (`psutil`), ~3% CPU overhead |
| **Crash-Safe** | `fsync()` after every write — data survives kernel panics |
| **Adaptive Burst Mode** | Increases recording frequency during high-load events |
| **Ring Buffer** | Automatic file rotation with gzip compression — bounded disk usage |
| **Security-Hardened** | Sensitive data redaction, restrictive file permissions, zero network exposure |
| **Cross-Platform** | Linux & Windows support |
| **Integrity Verified** | SHA-256 checksums on every snapshot to detect tampering |

---

## 🚀 Quick Start

### 1. Install

```bash
# Clone or copy the files
pip install psutil

# Verify installation
python blackbox.py --check
```

### 2. Record

```bash
# Start recording with defaults (30s interval, /var/lib/server-blackbox)
python blackbox.py

# Custom interval and directory
python blackbox.py --interval 15 --output-dir /data/blackbox

# Single snapshot to stdout (for testing)
python blackbox.py --oneshot
```

### 3. Analyze (after a crash)

```bash
# Generate diagnostic report
python analyzer.py /var/lib/server-blackbox

# Last 60 minutes only
python analyzer.py /var/lib/server-blackbox --last 60

# Machine-readable JSON output
python analyzer.py /var/lib/server-blackbox --json

# Save report to file
python analyzer.py /var/lib/server-blackbox -o crash-report.txt
```

### 4. Install as Service (Linux)

```bash
sudo bash install.sh
# That's it! Auto-starts on boot with systemd hardening.

# Uninstall
sudo bash uninstall.sh
```

---

## 📊 What Gets Recorded

Every snapshot (default: every 30 seconds) captures:

### System
- Hostname, OS, kernel version, architecture
- Uptime, boot time, logged-in users

### CPU
- Overall & per-core usage percentage
- Load average (1m, 5m, 15m)
- CPU times breakdown (user, system, idle, iowait, steal, irq, softirq)
- Context switches, interrupts, syscalls
- CPU frequency (current/min/max)

### Memory
- Virtual: total, available, used, free, percent, buffers, cached, shared, slab
- Swap: total, used, free, percent, swap-in/swap-out counters

### Disk
- Per-partition: device, mountpoint, fstype, total, used, free, percent
- I/O counters: read/write counts, bytes, times, busy time

### Network
- Per-interface: bytes/packets sent/received, errors, drops
- Interface addresses (IPv4, IPv6)
- Throughput rates (bytes/sec, calculated between snapshots)

### Connections
- Total connection count
- Breakdown by state (ESTABLISHED, LISTEN, TIME_WAIT, CLOSE_WAIT, etc.)
- Listening ports with PIDs
- Sample of established connections

### Processes (Top 25 by CPU+Memory)
- PID, name, status, username
- CPU%, Memory%, RSS, VMS
- Thread count, nice value
- Command line (sanitized — sensitive args redacted)
- Process start time
- Zombie process count

### Services
- **Linux**: All systemd units (name, load state, active state, sub state) + failed units list
- **Windows**: All Windows services (name, display name, status, start type)

### Sensors
- CPU/GPU temperatures (current, high, critical thresholds)
- Fan speeds (RPM)
- Battery status (if applicable)

### Filesystem
- System-wide file descriptor usage (allocated/free/max)

### Kernel (Linux only)
- Last 30 dmesg error/warning/critical lines
- OOM killer events
- Key /proc/vmstat counters (pgfault, pgmajfault, oom_kill, pswpin/pswpout, nr_dirty, nr_writeback)
- Pressure Stall Information (PSI) for CPU, memory, I/O

### Security (Linux only)
- SELinux status
- Failed SSH login attempts (last 5 minutes)
- Firewall rule count (iptables)

---

## 🔥 Burst Mode

When thresholds are exceeded, the recording interval automatically drops from 30s to **5s** for 5 minutes — capturing critical pre-crash data in high resolution:

| Trigger | Default Threshold |
|---|---|
| CPU Usage | ≥ 90% |
| Memory Usage | ≥ 90% |
| Disk Usage | ≥ 95% |

Configure thresholds:
```bash
python blackbox.py --cpu-threshold 85 --mem-threshold 85
```

---

## 📁 File Structure

```
/var/lib/server-blackbox/
├── blackbox.jsonl          # Current recording (JSONL format)
├── blackbox.1.jsonl.gz     # Previous rotation (compressed)
├── blackbox.2.jsonl.gz     # Older rotation
├── blackbox.3.jsonl.gz     # Oldest rotation
├── heartbeat               # Last-alive timestamp
└── blackbox.pid            # PID of running instance
```

### Storage Estimates

| Interval | Snapshot Size | Per Hour | Per Day | Per Week |
|---|---|---|---|---|
| 30s | ~5 KB | ~600 KB | ~14 MB | ~100 MB |
| 15s | ~5 KB | ~1.2 MB | ~28 MB | ~200 MB |
| 5s (burst) | ~5 KB | ~3.6 MB | ~86 MB | — |

Default max file size: **50 MB** with 3 archives = **~200 MB max total**.

---

## 🔒 Security Design

### Data Protection
- **Sensitive Data Redaction**: Passwords, tokens, API keys, secrets in command lines and environment variables are automatically replaced with `***`
- **File Permissions**: Data directory `0700`, files `0600` (Unix) — only the service user can read
- **Integrity Hashes**: Each snapshot includes a SHA-256 checksum for tamper detection

### Process Isolation (systemd)
- `NoNewPrivileges=yes` — no privilege escalation
- `ProtectSystem=strict` — read-only filesystem except data dir
- `ProtectHome=yes` — no access to /home
- `PrivateTmp=yes` — isolated /tmp
- `MemoryDenyWriteExecute=yes` — no W+X memory
- `RestrictNamespaces=yes` — no namespace manipulation
- `SystemCallArchitectures=native` — only native syscalls
- Minimal capabilities: `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`

### Code Security
- **No `eval()`/`exec()`** — zero dynamic code execution
- **No `shell=True`** — all subprocess calls use list arguments
- **No network exposure** — doesn't open any ports
- **Input validation** — all CLI arguments validated
- **Exception isolation** — each collector catches its own errors
- **Bounded memory** — string truncation, limited process/connection counts
- **PID file** — prevents duplicate instances

---

## 📋 CLI Reference

### blackbox.py

```
usage: blackbox [--interval N] [--burst-interval N] [--burst-duration N]
                [--top-processes N] [--max-size-mb N] [--max-archives N]
                [--output-dir DIR] [--cpu-threshold N] [--mem-threshold N]
                [--log-level LEVEL] [--oneshot] [--check] [--version]

Options:
  --interval N          Seconds between snapshots (default: 30)
  --burst-interval N    Burst-mode interval (default: 5)
  --burst-duration N    Burst-mode window in seconds (default: 300)
  --top-processes N     Processes per snapshot (default: 25)
  --max-size-mb N       Max file size in MiB (default: 50)
  --max-archives N      Rotated archives to keep (default: 3)
  --output-dir DIR      Output directory
  --cpu-threshold N     CPU% for burst trigger (default: 90)
  --mem-threshold N     Mem% for burst trigger (default: 90)
  --log-level LEVEL     DEBUG|INFO|WARNING|ERROR (default: WARNING)
  --oneshot             Single snapshot → stdout
  --check               Verify installation
```

### analyzer.py

```
usage: analyzer DIRECTORY [--last MINUTES] [--json] [--output FILE]

Arguments:
  DIRECTORY             Path to blackbox data directory

Options:
  --last MINUTES        Only analyze last N minutes
  --json                Output JSON instead of text
  --output FILE         Write report to file
```

---

## 📈 Analyzer Report Sections

The diagnostic report includes:

1. **Overview** — Server info, time range, snapshot count
2. **Last Snapshot Summary** — CPU, memory, disk, connections at crash time
3. **Top Processes** — Resource-hungry processes at crash time
4. **Anomaly Timeline** — Chronological list of detected issues:
   - 🔴 CRITICAL: CPU >95%, Memory >95%, Disk >98%, OOM events, Failed services, Network errors
   - 🟡 WARNING: CPU >85%, Memory >85%, Disk >90%, Memory leaks, Zombie processes, Connection leaks
5. **Resource Trends** — Min/avg/max for CPU and memory, growth detection
6. **Listening Ports** — All open ports at crash time
7. **Failed Services** — Systemd units in failed state
8. **Kernel Errors** — Last dmesg entries
9. **Security Status** — SELinux, SSH failures, firewall
10. **Recommendations** — Actionable fixes based on detected issues

---

## 🏗️ Architecture

```
                    ┌─────────────────────────┐
                    │    ServerBlackBox        │
                    │    (blackbox.py)         │
                    ├─────────────────────────┤
                    │                         │
                    │  ┌──────────────────┐   │
                    │  │   Collectors     │   │
                    │  │  CPU │ MEM │ DISK│   │
  psutil ──────────►│  │  NET │ PROC│ SVC│   │
  /proc  ──────────►│  │  KERN│ SEC │ FS │   │
  systemctl ───────►│  │  SENS│ CONN│    │   │
                    │  └───────┬──────────┘   │
                    │          │               │
                    │          ▼               │
                    │  ┌──────────────────┐   │
                    │  │   Sanitizer      │   │
                    │  │  (redact secrets)│   │
                    │  └───────┬──────────┘   │
                    │          │               │
                    │          ▼               │
                    │  ┌──────────────────┐   │
                    │  │  RingFile        │   │
                    │  │  (JSONL + rotate │   │
                    │  │   + gzip + fsync)│   │
                    │  └───────┬──────────┘   │
                    │          │               │
                    └──────────┼───────────────┘
                               │
                               ▼
                    ┌─────────────────────────┐
                    │  blackbox.jsonl          │
                    │  blackbox.1.jsonl.gz     │
                    │  blackbox.2.jsonl.gz     │
                    └─────────────────────────┘
                               │
                               ▼
                    ┌─────────────────────────┐
                    │    Analyzer              │
                    │    (analyzer.py)         │
                    │                         │
                    │  Load → Analyze → Report│
                    └─────────────────────────┘
```

---

## 📄 License

MIT — free for commercial and personal use.
