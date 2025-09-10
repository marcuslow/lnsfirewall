# psutil_stub.py (FreeBSD/pfSense-friendly)
# Provides a minimal subset of psutil APIs used by the client, with safer fallbacks

import os
import shutil
import subprocess
import time
from types import SimpleNamespace

# Helpers

def _run(cmd):
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return ""

def _sysctl(name, default=None):
    out = _run(["sysctl", "-n", name])
    out = out.strip()
    return out if out else default

def _sysctl_int(name, default=0):
    try:
        val = _sysctl(name, None)
        return int(val) if val is not None else default
    except Exception:
        return default

# Public API

def boot_time():
    """Return system boot time (epoch seconds)."""
    try:
        out = _run(["sysctl", "-n", "kern.boottime"])  # e.g., { sec = 1691234567, usec = 0 } ...
        if "sec =" in out:
            sec = int(out.split("sec =", 1)[1].split(",", 1)[0].strip())
            return sec
    except Exception:
        pass
    # Fallback: pretend boot was 1 second ago if parsing fails
    return int(time.time()) - 1


def virtual_memory():
    """Approximate virtual memory stats using FreeBSD sysctl counters."""
    try:
        total = _sysctl_int("hw.physmem", 0)
        page_size = _sysctl_int("vm.stats.vm.v_page_size", 4096)
        free = _sysctl_int("vm.stats.vm.v_free_count", 0)
        inactive = _sysctl_int("vm.stats.vm.v_inactive_count", 0)
        cache = _sysctl_int("vm.stats.vm.v_cache_count", 0)
        # Some systems expose laundry; include if present
        laundry = _sysctl_int("vm.stats.vm.v_laundry_count", 0)
        available = (free + inactive + cache + laundry) * page_size
        used = max(0, total - available)
        percent = round((used / total) * 100.0, 2) if total > 0 else 0.0
        return SimpleNamespace(total=total, available=available, percent=percent, used=used)
    except Exception:
        total = _sysctl_int("hw.physmem", 0)
        return SimpleNamespace(total=total, available=total, percent=0.0, used=0)


def disk_usage(path):
    """Return disk usage for path."""
    try:
        return shutil.disk_usage(path)
    except Exception:
        # Return a psutil-like object with zeros
        return SimpleNamespace(total=0, used=0, free=0)


def cpu_percent(interval=1):
    """Return a rough CPU utilization percentage (1-min load average / cores)."""
    try:
        # Optionally wait a bit to mimic psutil's interval behavior (non-blocking here)
        if interval and interval > 0:
            time.sleep(min(interval, 1))
        load1, _, _ = os.getloadavg()
        cores = os.cpu_count() or 1
        pct = (load1 / max(1, cores)) * 100.0
        # Clamp to [0, 100]
        return max(0.0, min(100.0, round(pct, 2)))
    except Exception:
        return 0.0


def cpu_count():
    return os.cpu_count() or 1


def net_io_counters(pernic=True):
    """Return per-interface I/O counters by parsing `netstat -ibn`.
    Returns a dict[iface] = object(bytes_sent, bytes_recv, packets_sent, packets_recv)
    """
    out = _run(["netstat", "-ibn"]).splitlines()
    if not out:
        return {}

    # Find header indices
    header_idx = None
    for i, line in enumerate(out):
        if line.lower().strip().startswith("name"):
            header_idx = i
            break
    if header_idx is None:
        return {}

    headers = out[header_idx].split()
    def find_col(*names):
        for j, h in enumerate(headers):
            for n in names:
                if h.lower() == n:
                    return j
        return -1

    idx_name = find_col("name")
    idx_network = find_col("network")
    idx_ipkts = find_col("ipkts", "iPackets".lower())
    idx_opkts = find_col("opkts", "oPackets".lower())
    idx_ibytes = find_col("ibytes", "iBytes".lower())
    idx_obytes = find_col("obytes", "oBytes".lower())

    stats = {}
    # Parse subsequent lines
    for line in out[header_idx + 1:]:
        parts = line.split()
        if len(parts) <= max(idx_name, idx_network, idx_ipkts, idx_opkts, idx_ibytes, idx_obytes, 0):
            continue
        name = parts[idx_name]
        # Prefer the <Link#…> row (hardware counters)
        network_val = parts[idx_network] if idx_network >= 0 else ""
        if network_val and not network_val.startswith("<Link"):
            # skip non-link rows; we'll collect the link row
            continue

        def to_int(s):
            try:
                return int(s)
            except Exception:
                return 0

        ibytes = to_int(parts[idx_ibytes]) if idx_ibytes >= 0 else 0
        obytes = to_int(parts[idx_obytes]) if idx_obytes >= 0 else 0
        ipkts = to_int(parts[idx_ipkts]) if idx_ipkts >= 0 else 0
        opkts = to_int(parts[idx_opkts]) if idx_opkts >= 0 else 0

        stats[name] = SimpleNamespace(
            bytes_sent=obytes,
            bytes_recv=ibytes,
            packets_sent=opkts,
            packets_recv=ipkts,
        )

    return stats
