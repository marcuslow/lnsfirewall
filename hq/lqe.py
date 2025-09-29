import json
import gzip
import base64
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class LogEntry:
    timestamp: Optional[str]
    action: Optional[str]
    interface: Optional[str]
    proto: Optional[str]
    src: Optional[str]
    src_port: Optional[int]
    dst: Optional[str]
    dst_port: Optional[int]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogEntry":
        """Create LogEntry from dict, handling multiple field naming conventions"""
        # Normalize field names from client data
        return cls(
            timestamp=data.get('timestamp'),
            action=data.get('action'),
            interface=data.get('interface'),
            # Handle both 'proto'/'protocol' field names
            proto=data.get('proto') or data.get('protocol'),
            # Handle both 'src'/'source_ip' field names
            src=data.get('src') or data.get('source_ip'),
            # Handle both 'src_port'/'source_port' field names
            src_port=cls._safe_int(data.get('src_port') or data.get('source_port')),
            # Handle both 'dst'/'dest_ip' field names
            dst=data.get('dst') or data.get('dest_ip'),
            # Handle both 'dst_port'/'dest_port' field names
            dst_port=cls._safe_int(data.get('dst_port') or data.get('dest_port')),
        )

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        """Safely convert value to int"""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
    reason: Optional[str] = None
    feed: Optional[str] = None
    country: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


SERVICE_PORTS = {
    "ssh": 22,
    "http": 80,
    "https": 443,
    "ftp": 21,
}


class LogQueryEngine:
    """In-memory analysis over stored firewall logs (no raw log content sent to AI)."""

    def __init__(self, entries: Iterable[Dict[str, Any]]):
        self.entries: List[LogEntry] = [LogEntry.from_dict(e) for e in entries]



    # Filters
    def filter_blocked(self) -> List[LogEntry]:
        return [x for x in self.entries if x.action in ("block", "blocked", "reject")]

    def filter_allowed(self) -> List[LogEntry]:
        return [x for x in self.entries if x.action in ("pass", "allow", "allowed")]

    def filter_by_ip_fragment(self, frag: str) -> List[LogEntry]:
        f = frag.strip()
        if not f:
            return []
        return [x for x in self.entries if (x.src and f in x.src) or (x.dst and f in x.dst)]

    def filter_by_port(self, port: int) -> List[LogEntry]:
        return [x for x in self.entries if x.src_port == port or x.dst_port == port]

    def filter_by_service(self, name: str) -> List[LogEntry]:
        p = SERVICE_PORTS.get(name.lower())
        if p is None:
            return []
        return self.filter_by_port(p)

    def detect_brute_force(self, ports: List[int] = None, threshold: int = 5) -> List[LogEntry]:
        """Detect potential brute-force: multiple blocks from same IP on auth ports"""
        if ports is None:
            ports = [22, 3389, 445, 21, 23]  # SSH, RDP, SMB, FTP, Telnet

        blocked = self.filter_blocked()
        ip_attempts = defaultdict(int)

        # Count attempts per IP on auth ports
        for entry in blocked:
            if entry.dst_port in ports and entry.src:
                ip_attempts[entry.src] += 1

        # Return entries from IPs that exceed threshold
        suspicious_ips = {ip for ip, count in ip_attempts.items() if count >= threshold}
        return [entry for entry in blocked if entry.src in suspicious_ips and entry.dst_port in ports]

    def detect_port_scans(self, threshold: int = 10) -> List[LogEntry]:
        """Detect potential port scans: same IP hitting many different ports"""
        ip_ports = defaultdict(set)

        for entry in self.entries:
            if entry.src and entry.dst_port:
                ip_ports[entry.src].add(entry.dst_port)

        # Find IPs that hit many different ports
        scanning_ips = {ip for ip, ports in ip_ports.items() if len(ports) >= threshold}
        return [entry for entry in self.entries if entry.src in scanning_ips]

    def get_top_blocked_ips(self, top_n: int = 10) -> List[Tuple[str, int]]:
        """Get top IPs by number of blocked connections"""
        blocked = self.filter_blocked()
        ip_counts = Counter(entry.src for entry in blocked if entry.src)
        return ip_counts.most_common(top_n)

    # Summaries
    def summarize(self, top_n: int = 10) -> Dict[str, Any]:
        total = len(self.entries)
        actions = Counter(x.action or "" for x in self.entries)
        protos = Counter(x.proto or "" for x in self.entries)
        src_ips = Counter(x.src or "" for x in self.entries if x.src)
        dst_ips = Counter(x.dst or "" for x in self.entries if x.dst)
        dst_ports = Counter(x.dst_port for x in self.entries if x.dst_port is not None)
        src_ports = Counter(x.src_port for x in self.entries if x.src_port is not None)

        def top(counter):
            return [
                {"value": k, "count": v}
                for k, v in counter.most_common(top_n)
            ]

        return {
            "total_entries": total,
            "actions": dict(actions),
            "protocols": dict(protos),
            "top_src_ips": top(src_ips),
            "top_dst_ips": top(dst_ips),
            "top_dst_ports": top(dst_ports),
            "top_src_ports": top(src_ports),
            "blocked_count": sum(actions.get(k, 0) for k in ("block", "blocked", "reject")),
            "allowed_count": sum(actions.get(k, 0) for k in ("pass", "allow", "allowed")),
        }

    @staticmethod
    def from_db(db_path: str, client_id: Optional[str], since_days: int = 7) -> "LogQueryEngine":
        import sqlite3
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        start = (datetime.now() - timedelta(days=since_days)).isoformat()

        entries: List[Dict[str, Any]] = []

        # First try the logs table (new storage method)
        if client_id:
            cur.execute(
                """
                SELECT log_data, compressed
                FROM logs
                WHERE (client_id = ?) AND (timestamp >= ?)
                ORDER BY timestamp DESC
                """,
                (client_id, start),
            )
        else:
            cur.execute(
                """
                SELECT log_data, compressed
                FROM logs
                WHERE (timestamp >= ?)
                ORDER BY timestamp DESC
                """,
                (start,),
            )

        for log_data, compressed in cur.fetchall():
            if compressed:
                try:
                    payload = gzip.decompress(base64.b64decode(log_data.encode("utf-8"))).decode("utf-8")
                except Exception:
                    continue
            else:
                payload = log_data
            try:
                chunk = json.loads(payload)
                if isinstance(chunk, list):
                    entries.extend(chunk)
            except Exception:
                continue

        # If no entries found in logs table, try command responses (fallback for existing data)
        if not entries:
            if client_id:
                cur.execute(
                    """
                    SELECT response_data
                    FROM commands
                    WHERE (client_id = ?) AND (command_type = 'get_logs') AND (status = 'completed') AND (created_at >= ?)
                    ORDER BY created_at DESC
                    """,
                    (client_id, start),
                )
            else:
                cur.execute(
                    """
                    SELECT response_data
                    FROM commands
                    WHERE (command_type = 'get_logs') AND (status = 'completed') AND (created_at >= ?)
                    ORDER BY created_at DESC
                    """,
                    (start,),
                )

            for (response_data,) in cur.fetchall():
                if response_data:
                    try:
                        response = json.loads(response_data)
                        if isinstance(response, dict) and 'logs' in response:
                            logs = response['logs']
                            if isinstance(logs, str):
                                # Compressed logs
                                if response.get('compressed', False):
                                    try:
                                        payload = gzip.decompress(base64.b64decode(logs.encode("utf-8"))).decode("utf-8")
                                        chunk = json.loads(payload)
                                        if isinstance(chunk, list):
                                            entries.extend(chunk)
                                    except Exception:
                                        continue
                                else:
                                    # Uncompressed string
                                    try:
                                        chunk = json.loads(logs)
                                        if isinstance(chunk, list):
                                            entries.extend(chunk)
                                    except Exception:
                                        continue
                            elif isinstance(logs, list):
                                # Direct list of log entries
                                entries.extend(logs)
                    except Exception:
                        continue

        conn.close()
        return LogQueryEngine(entries)

