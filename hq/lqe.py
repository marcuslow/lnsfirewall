import json
import gzip
import base64
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple
import logging
import requests
import ipaddress
import os

# Optional geolocation support
try:
    import ipinfo
    IPINFO_AVAILABLE = True
except ImportError:
    IPINFO_AVAILABLE = False

# Optional offline GeoIP2 support (free MaxMind GeoLite2 database)
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

logger = logging.getLogger(__name__)


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

    # Helper function for IP validation
    @staticmethod
    def is_valid_external_ip(ip_str: str) -> bool:
        """
        Check if string is a valid public IPv4 or IPv6 address.
        Filters out:
        - Invalid IPs
        - Private/RFC1918 IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
        - Loopback (127.x.x.x)
        - Link-local (169.254.x.x)
        - Reserved/special IPs

        This ensures we only analyze EXTERNAL attackers, not internal traffic.
        """
        if not ip_str or ip_str in ['RTALERT', '0.0.0.0', '']:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            # Filter out private/internal IPs - these are NOT external attackers
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                return False
            return True
        except ValueError:
            return False

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
        """
        DEPRECATED: Use detect_scanning_activity() for comprehensive scan detection.

        Legacy method: Detect potential port scans (same IP hitting many different ports).
        This only detects vertical scans without destination tracking.
        """
        ip_ports = defaultdict(set)

        for entry in self.entries:
            if entry.src and entry.dst_port:
                ip_ports[entry.src].add(entry.dst_port)

        # Find IPs that hit many different ports
        scanning_ips = {ip for ip, ports in ip_ports.items() if len(ports) >= threshold}
        return [entry for entry in self.entries if entry.src in scanning_ips]

    def detect_scanning_activity(
        self,
        port_scan_threshold: int = 15,
        network_sweep_threshold: int = 15
    ) -> Dict[str, Any]:
        """
        Detects potential port scanning and network sweeping activities from logs.

        This is a critical early-warning tool. Port scanning is a common precursor to
        a targeted attack, used by adversaries to discover open ports and vulnerable services.
        Detecting this allows for proactive blocking of reconnaissance activities.

        Vertical Scan (Port Scan): One source IP probing many unique ports on ONE target host.
        Horizontal Scan (Network Sweep): One source IP probing the SAME port across MANY hosts.

        :param port_scan_threshold: Number of unique ports from one source to one destination
                                    to trigger a vertical scan alert (default: 15)
        :param network_sweep_threshold: Number of unique hosts targeted on the same port
                                        by one source to trigger a horizontal scan alert (default: 15)
        :return: Dictionary with vertical_scans_detected and horizontal_scans_detected
        """
        # Work with blocked traffic only (reconnaissance attempts are typically blocked)
        blocked = self.filter_blocked()

        # 1. VERTICAL PORT SCAN DETECTION
        # Track: source_ip -> destination_ip -> set of unique ports
        vertical_scan_data = defaultdict(lambda: defaultdict(set))

        for entry in blocked:
            # Only analyze EXTERNAL attackers (filter out internal/private IPs)
            if entry.src and entry.dst and entry.dst_port and self.is_valid_external_ip(entry.src):
                vertical_scan_data[entry.src][entry.dst].add(entry.dst_port)

        # Find source-destination pairs exceeding threshold
        vertical_scans = []
        for src_ip, destinations in vertical_scan_data.items():
            for dst_ip, ports in destinations.items():
                unique_ports_count = len(ports)
                if unique_ports_count >= port_scan_threshold:
                    vertical_scans.append({
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "unique_ports_scanned": unique_ports_count,
                        "ports_sample": sorted(list(ports))[:10]  # Show first 10 ports
                    })

        # Sort by severity (most ports scanned first)
        vertical_scans.sort(key=lambda x: x["unique_ports_scanned"], reverse=True)

        # 2. HORIZONTAL SCAN (NETWORK SWEEP) DETECTION
        # Track: source_ip -> destination_port -> set of unique destination IPs
        horizontal_scan_data = defaultdict(lambda: defaultdict(set))

        for entry in blocked:
            # Only analyze EXTERNAL attackers (filter out internal/private IPs)
            if entry.src and entry.dst and entry.dst_port and self.is_valid_external_ip(entry.src):
                horizontal_scan_data[entry.src][entry.dst_port].add(entry.dst)

        # Find source-port combinations exceeding threshold
        horizontal_scans = []
        for src_ip, ports in horizontal_scan_data.items():
            for dst_port, hosts in ports.items():
                unique_hosts_count = len(hosts)
                if unique_hosts_count >= network_sweep_threshold:
                    horizontal_scans.append({
                        "source_ip": src_ip,
                        "destination_port": dst_port,
                        "unique_hosts_swept": unique_hosts_count,
                        "hosts_sample": sorted(list(hosts))[:10]  # Show first 10 hosts
                    })

        # Sort by severity (most hosts swept first)
        horizontal_scans.sort(key=lambda x: x["unique_hosts_swept"], reverse=True)

        return {
            "vertical_scans_detected": vertical_scans,
            "horizontal_scans_detected": horizontal_scans,
            "total_vertical_scans": len(vertical_scans),
            "total_horizontal_scans": len(horizontal_scans),
            "summary": self._generate_scan_summary(vertical_scans, horizontal_scans)
        }

    def _generate_scan_summary(self, vertical_scans: List[Dict], horizontal_scans: List[Dict]) -> str:
        """Generate human-readable summary of scanning activity"""
        if not vertical_scans and not horizontal_scans:
            return "No significant scanning activity detected."

        summary_parts = []

        if vertical_scans:
            top_scanner = vertical_scans[0]
            summary_parts.append(
                f"Detected {len(vertical_scans)} vertical port scan(s). "
                f"Top threat: {top_scanner['source_ip']} scanned "
                f"{top_scanner['unique_ports_scanned']} ports on {top_scanner['destination_ip']}."
            )

        if horizontal_scans:
            top_sweeper = horizontal_scans[0]
            summary_parts.append(
                f"Detected {len(horizontal_scans)} horizontal network sweep(s). "
                f"Top threat: {top_sweeper['source_ip']} swept port {top_sweeper['destination_port']} "
                f"across {top_sweeper['unique_hosts_swept']} hosts."
            )

        return " ".join(summary_parts)

    def get_top_blocked_ips(self, top_n: int = 10) -> List[Tuple[str, int]]:
        """Get top IPs by number of blocked connections"""
        blocked = self.filter_blocked()
        ip_counts = Counter(entry.src for entry in blocked if entry.src)
        return ip_counts.most_common(top_n)

    def map_geographic_threats(
        self,
        ipinfo_token: Optional[str] = None,
        top_n: int = 10,
        cache_db_path: Optional[str] = None,
        blocked_only: bool = True,
        max_api_lookups: int = 10,
        geoip2_db_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Enriches source IPs with geolocation data to identify traffic origins.

        Uses a hybrid two-tier approach:
        1. Free offline GeoIP2 database (GeoLite2) for ALL IPs - country/city data
        2. ipinfo.io API for top X attackers only - detailed ISP/org information

        This provides vital context. Traffic from unexpected or high-risk countries can
        indicate a targeted campaign or automated botnet activity, helping analysts
        prioritize threats. It moves analysis from 'who' to 'where'.

        :param ipinfo_token: API token for ipinfo.io service (optional, for org/ISP details)
        :param top_n: Number of top countries to report (default: 10)
        :param cache_db_path: Path to SQLite database for caching geolocation data
        :param blocked_only: Only analyze blocked traffic (default: True, recommended)
        :param max_api_lookups: Maximum number of ipinfo API lookups for org details (default: 10)
        :param geoip2_db_path: Path to GeoLite2 .mmdb database file (optional, for offline lookups)
        :return: Dictionary with geographic threat analysis
        """
        # Filter to blocked traffic only (attackers, not legitimate users)
        entries_to_analyze = self.filter_blocked() if blocked_only else self.entries

        # Extract unique source IPs to minimize API calls
        # Filter out invalid/private IPs - only analyze EXTERNAL attackers
        unique_ips = list(set(entry.src for entry in entries_to_analyze if entry.src and self.is_valid_external_ip(entry.src)))

        if not unique_ips:
            return {
                "success": False,
                "summary": "No valid source IPs available for geographic analysis.",
                "total_ips": 0
            }

        # Try to load from cache first
        ip_to_country = {}
        ips_needing_lookup = set(unique_ips)

        if cache_db_path:
            try:
                import sqlite3
                conn = sqlite3.connect(cache_db_path)
                cur = conn.cursor()

                # Create cache table if it doesn't exist
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS ip_geolocation_cache (
                        ip TEXT PRIMARY KEY,
                        country_code TEXT,
                        country_name TEXT,
                        city TEXT,
                        region TEXT,
                        org TEXT,
                        cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                conn.commit()

                # Load cached data
                placeholders = ','.join('?' * len(unique_ips))
                cur.execute(f'''
                    SELECT ip, country_code, country_name, city, region, org
                    FROM ip_geolocation_cache
                    WHERE ip IN ({placeholders})
                ''', unique_ips)

                for row in cur.fetchall():
                    ip, country_code, country_name, city, region, org = row
                    ip_to_country[ip] = {
                        'country_code': country_code,
                        'country_name': country_name,
                        'city': city,
                        'region': region,
                        'org': org,
                        'cached': True
                    }
                    ips_needing_lookup.discard(ip)

                conn.close()
                logger.info(f"Loaded {len(ip_to_country)} IPs from cache, {len(ips_needing_lookup)} need lookup")
            except Exception as e:
                logger.warning(f"Failed to load from cache: {e}")

        # TIER 1: Use free offline GeoIP2 database for ALL remaining IPs (country/city only)
        geoip2_lookups = 0
        if ips_needing_lookup and geoip2_db_path:
            if not GEOIP2_AVAILABLE:
                logger.warning("geoip2 library not available. Install with: pip install geoip2")
            elif not os.path.exists(geoip2_db_path):
                logger.warning(f"GeoIP2 database not found at: {geoip2_db_path}")
            else:
                try:
                    import geoip2.database
                    import geoip2.errors

                    reader = geoip2.database.Reader(geoip2_db_path)
                    logger.info(f"Using GeoIP2 offline database for {len(ips_needing_lookup)} IPs")

                    ips_resolved_by_geoip2 = []
                    for ip in list(ips_needing_lookup):
                        try:
                            # Try country lookup first (smaller DB, faster)
                            try:
                                response = reader.country(ip)
                                country_code = response.country.iso_code
                                country_name = response.country.name
                                city = None
                            except AttributeError:
                                # Might be City database instead
                                response = reader.city(ip)
                                country_code = response.country.iso_code
                                country_name = response.country.name
                                city = response.city.name if response.city.name else None

                            if country_code:
                                ip_to_country[ip] = {
                                    'country_code': country_code,
                                    'country_name': country_name,
                                    'city': city,
                                    'region': None,
                                    'org': None,  # Not available in free GeoIP2
                                    'cached': False,
                                    'source': 'geoip2_offline'
                                }
                                ips_resolved_by_geoip2.append(ip)
                                ips_needing_lookup.discard(ip)
                                geoip2_lookups += 1
                        except (geoip2.errors.AddressNotFoundError, ValueError):
                            # IP not in database or invalid
                            pass
                        except Exception as e:
                            logger.debug(f"GeoIP2 lookup failed for {ip}: {e}")

                    reader.close()
                    logger.info(f"GeoIP2 resolved {len(ips_resolved_by_geoip2)} IPs, {len(ips_needing_lookup)} still need lookup")

                    # Cache GeoIP2 results
                    if cache_db_path and ips_resolved_by_geoip2:
                        try:
                            import sqlite3
                            conn = sqlite3.connect(cache_db_path)
                            cur = conn.cursor()
                            for ip in ips_resolved_by_geoip2:
                                data = ip_to_country[ip]
                                cur.execute('''
                                    INSERT OR REPLACE INTO ip_geolocation_cache
                                    (ip, country_code, country_name, city, region, org)
                                    VALUES (?, ?, ?, ?, ?, ?)
                                ''', (ip, data['country_code'], data['country_name'],
                                      data['city'], data['region'], data['org']))
                            conn.commit()
                            conn.close()
                            logger.info(f"Cached {len(ips_resolved_by_geoip2)} GeoIP2 results")
                        except Exception as e:
                            logger.warning(f"Failed to cache GeoIP2 results: {e}")

                except Exception as e:
                    logger.warning(f"Failed to use GeoIP2 database: {e}")

        # TIER 2: Perform ipinfo API lookups for top X uncached IPs (for org/ISP details)
        if ips_needing_lookup:
            if not IPINFO_AVAILABLE:
                return {
                    "success": False,
                    "error": "ipinfo library not installed. Install with: pip install ipinfo",
                    "cached_results": len(ip_to_country),
                    "missing_results": len(ips_needing_lookup)
                }

            if not ipinfo_token:
                return {
                    "success": False,
                    "error": "ipinfo_token required for API lookups. Set IPINFO_TOKEN environment variable.",
                    "cached_results": len(ip_to_country),
                    "missing_results": len(ips_needing_lookup)
                }

            # Limit API lookups to stay within quota
            skipped_ips = 0
            if len(ips_needing_lookup) > max_api_lookups:
                logger.warning(f"Too many IPs to check ({len(ips_needing_lookup)}). Prioritizing top {max_api_lookups} most frequent attackers.")

                # Count how many times each IP appears in blocked logs
                from collections import Counter
                ip_counts = Counter(entry.src for entry in entries_to_analyze if entry.src and self.is_valid_external_ip(entry.src))

                # Get top N most frequent IPs that need lookup
                top_ips_needing_lookup = [ip for ip, count in ip_counts.most_common() if ip in ips_needing_lookup][:max_api_lookups]
                ips_to_lookup = top_ips_needing_lookup
                skipped_ips = len(ips_needing_lookup) - len(ips_to_lookup)
                logger.info(f"Checking top {len(ips_to_lookup)} IPs, skipping {skipped_ips} less frequent IPs")
            else:
                ips_to_lookup = list(ips_needing_lookup)

            try:
                handler = ipinfo.getHandler(ipinfo_token)

                # Batch lookup for efficiency
                details = handler.getBatchDetails(ips_to_lookup)

                # Cache the results
                if cache_db_path:
                    try:
                        import sqlite3
                        conn = sqlite3.connect(cache_db_path)
                        cur = conn.cursor()

                        for ip, detail in details.items():
                            # getBatchDetails() returns dict[str, dict], not dict[str, Details]
                            # Single getDetails() returns Details object with .all, but batch returns plain dicts
                            data = detail if isinstance(detail, dict) else (detail.all if hasattr(detail, 'all') else {})
                            country_code = data.get('country', None)
                            country_name = data.get('country_name', None)
                            city = data.get('city', None)
                            region = data.get('region', None)
                            org = data.get('org', None)

                            cur.execute('''
                                INSERT OR REPLACE INTO ip_geolocation_cache
                                (ip, country_code, country_name, city, region, org)
                                VALUES (?, ?, ?, ?, ?, ?)
                            ''', (ip, country_code, country_name, city, region, org))

                            ip_to_country[ip] = {
                                'country_code': country_code,
                                'country_name': country_name,
                                'city': city,
                                'region': region,
                                'org': org,
                                'cached': False
                            }

                        conn.commit()
                        conn.close()
                        logger.info(f"Cached {len(details)} new IP lookups")
                    except Exception as e:
                        logger.warning(f"Failed to cache results: {e}")
                else:
                    # No caching, just store in memory
                    for ip, detail in details.items():
                        data = detail if isinstance(detail, dict) else (detail.all if hasattr(detail, 'all') else {})
                        ip_to_country[ip] = {
                            'country_code': data.get('country', None),
                            'country_name': data.get('country_name', None),
                            'city': data.get('city', None),
                            'region': data.get('region', None),
                            'org': data.get('org', None),
                            'cached': False
                        }

            except Exception as e:
                return {
                    "success": False,
                    "error": f"Failed to get IP details from ipinfo API: {str(e)}",
                    "cached_results": len(ip_to_country)
                }

        # Aggregate by country
        country_counts = Counter()
        country_to_ips = defaultdict(list)

        for entry in entries_to_analyze:
            if entry.src and entry.src in ip_to_country:
                geo_data = ip_to_country[entry.src]
                country_code = geo_data.get('country_code')
                if country_code:
                    country_counts[country_code] += 1
                    # Keep sample of UNIQUE IPs per country (avoid duplicates)
                    if entry.src not in country_to_ips[country_code] and len(country_to_ips[country_code]) < 5:
                        country_to_ips[country_code].append(entry.src)

        # Build detailed country breakdown
        top_countries = []
        for country_code, count in country_counts.most_common(top_n):
            sample_ips = country_to_ips[country_code]
            sample_geo = ip_to_country.get(sample_ips[0], {})

            top_countries.append({
                'country_code': country_code,
                'country_name': sample_geo.get('country_name', country_code),
                'blocked_connections': count,
                'percentage': round((count / len(entries_to_analyze)) * 100, 2),
                'sample_ips': sample_ips,
                'sample_orgs': list(set(
                    ip_to_country.get(ip, {}).get('org', 'Unknown')
                    for ip in sample_ips
                ))[:3]
            })

        # Calculate actual API lookups performed (not just needed)
        actual_api_lookups = len(ips_to_lookup) if 'ips_to_lookup' in locals() else 0
        cache_hits = len([v for v in ip_to_country.values() if v.get('cached', False)])

        return {
            "success": True,
            "summary": f"Geographic analysis of {len(unique_ips)} unique source IPs from {len(entries_to_analyze)} blocked connections.",
            "total_unique_ips": len(unique_ips),
            "total_connections_analyzed": len(entries_to_analyze),
            "countries_detected": len(country_counts),
            "top_source_countries": top_countries,
            "geoip2_offline_lookups": geoip2_lookups,
            "ipinfo_api_lookups": actual_api_lookups,
            "cache_hits": cache_hits,
            "ips_skipped": skipped_ips if 'skipped_ips' in locals() else 0,
            "ips_resolved": len(ip_to_country),
            "ips_unresolved": len(unique_ips) - len(ip_to_country)
        }

    def correlate_with_threat_intel(
        self,
        abuseipdb_key: Optional[str] = None,
        cache_db_path: Optional[str] = None,
        blocked_only: bool = True,
        confidence_threshold: int = 50,
        max_age_days: int = 90,
        max_api_lookups: int = 10
    ) -> Dict[str, Any]:
        """
        Correlates source IPs against threat intelligence feeds (AbuseIPDB).

        This is a high-fidelity analysis tool. A match against a known malicious IP
        is a strong indicator of an active threat, moving beyond mere suspicion to
        confirmed malicious intent. It helps answer: 'Is this a known bad guy?'

        :param abuseipdb_key: API key for AbuseIPDB (optional if using cache)
        :param cache_db_path: Path to SQLite database for caching threat intel data
        :param blocked_only: Only analyze blocked traffic (default: True)
        :param confidence_threshold: Minimum abuse confidence score to flag (default: 50)
        :param max_age_days: Maximum age of reports to consider (default: 90)
        :param max_api_lookups: Maximum number of API lookups to perform (default: 10)
        :return: Dictionary with threat intelligence findings
        """
        # Filter to blocked traffic only (attackers, not legitimate users)
        entries_to_analyze = self.filter_blocked() if blocked_only else self.entries

        # Extract unique source IPs - only analyze EXTERNAL attackers
        unique_ips = list(set(entry.src for entry in entries_to_analyze if entry.src and self.is_valid_external_ip(entry.src)))

        if not unique_ips:
            return {
                "success": False,
                "summary": "No valid source IPs available for threat intelligence correlation.",
                "total_ips": 0
            }

        # Try to load from cache first
        ip_to_threat_data = {}
        ips_needing_lookup = set(unique_ips)
        skipped_ips = 0  # Track how many IPs we skip due to API limits

        if cache_db_path:
            try:
                import sqlite3
                conn = sqlite3.connect(cache_db_path)
                cur = conn.cursor()

                # Create cache table if it doesn't exist
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS threat_intel_cache (
                        ip TEXT PRIMARY KEY,
                        source TEXT,
                        abuse_confidence_score INTEGER,
                        total_reports INTEGER,
                        country_code TEXT,
                        isp TEXT,
                        usage_type TEXT,
                        is_tor INTEGER,
                        is_public_proxy INTEGER,
                        last_reported_at TEXT,
                        cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                conn.commit()

                # Load cached data (only recent cache entries, e.g., < 7 days old)
                placeholders = ','.join('?' * len(unique_ips))
                cur.execute(f'''
                    SELECT ip, source, abuse_confidence_score, total_reports,
                           country_code, isp, usage_type, is_tor, is_public_proxy, last_reported_at
                    FROM threat_intel_cache
                    WHERE ip IN ({placeholders})
                    AND cached_at >= datetime('now', '-7 days')
                ''', unique_ips)

                for row in cur.fetchall():
                    ip, source, score, reports, country, isp, usage, is_tor, is_proxy, last_reported = row
                    ip_to_threat_data[ip] = {
                        'source': source,
                        'abuse_confidence_score': score,
                        'total_reports': reports,
                        'country_code': country,
                        'isp': isp,
                        'usage_type': usage,
                        'is_tor': bool(is_tor),
                        'is_public_proxy': bool(is_proxy),
                        'last_reported_at': last_reported,
                        'cached': True
                    }
                    ips_needing_lookup.discard(ip)

                conn.close()
                logger.info(f"Loaded {len(ip_to_threat_data)} IPs from threat intel cache, {len(ips_needing_lookup)} need lookup")
            except Exception as e:
                logger.warning(f"Failed to load from threat intel cache: {e}")

        # Perform API lookups for uncached IPs
        if ips_needing_lookup:
            if not abuseipdb_key:
                return {
                    "success": False,
                    "error": "abuseipdb_key required for API lookups. Set ABUSEIPDB_KEY environment variable.",
                    "cached_results": len(ip_to_threat_data),
                    "missing_results": len(ips_needing_lookup)
                }

            # IMPORTANT: AbuseIPDB free tier has 1,000 requests/day limit
            # To conserve API quota, limit API calls to most frequent attackers
            skipped_ips = 0
            if len(ips_needing_lookup) > max_api_lookups:
                logger.warning(f"Too many IPs to check ({len(ips_needing_lookup)}). Prioritizing top {max_api_lookups} most frequent attackers.")

                # Count how many times each IP appears in blocked logs
                from collections import Counter
                ip_counts = Counter(entry.src for entry in entries_to_analyze if entry.src and self.is_valid_external_ip(entry.src))

                # Get top N most frequent IPs that need lookup
                top_ips_needing_lookup = [ip for ip, count in ip_counts.most_common() if ip in ips_needing_lookup][:max_api_lookups]
                ips_to_check = top_ips_needing_lookup
                skipped_ips = len(ips_needing_lookup) - len(ips_to_check)
                logger.info(f"Checking top {len(ips_to_check)} IPs, skipping {skipped_ips} less frequent IPs")
            else:
                ips_to_check = list(ips_needing_lookup)
                skipped_ips = 0

            headers = {
                'Accept': 'application/json',
                'Key': abuseipdb_key
            }

            api_calls_made = 0

            for ip in ips_to_check:
                try:
                    # Add small delay between requests to be respectful to API
                    import time
                    if api_calls_made > 0:
                        time.sleep(0.5)  # 500ms delay between requests

                    response = requests.get(
                        url='https://api.abuseipdb.com/api/v2/check',
                        params={'ipAddress': ip, 'maxAgeInDays': str(max_age_days)},
                        headers=headers,
                        timeout=10
                    )
                    response.raise_for_status()
                    api_calls_made += 1
                    report = response.json().get('data', {})

                    if report:
                        threat_data = {
                            'source': 'AbuseIPDB',
                            'abuse_confidence_score': report.get('abuseConfidenceScore', 0),
                            'total_reports': report.get('totalReports', 0),
                            'country_code': report.get('countryCode', 'N/A'),
                            'isp': report.get('isp', 'N/A'),
                            'usage_type': report.get('usageType', 'N/A'),
                            'is_tor': report.get('isTor', False),
                            'is_public_proxy': report.get('isPublic', False),
                            'last_reported_at': report.get('lastReportedAt', 'N/A'),
                            'cached': False
                        }

                        ip_to_threat_data[ip] = threat_data

                        # Cache the result
                        if cache_db_path:
                            try:
                                import sqlite3
                                conn = sqlite3.connect(cache_db_path)
                                cur = conn.cursor()
                                cur.execute('''
                                    INSERT OR REPLACE INTO threat_intel_cache
                                    (ip, source, abuse_confidence_score, total_reports, country_code,
                                     isp, usage_type, is_tor, is_public_proxy, last_reported_at)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                ''', (
                                    ip, 'AbuseIPDB', threat_data['abuse_confidence_score'],
                                    threat_data['total_reports'], threat_data['country_code'],
                                    threat_data['isp'], threat_data['usage_type'],
                                    int(threat_data['is_tor']), int(threat_data['is_public_proxy']),
                                    threat_data['last_reported_at']
                                ))
                                conn.commit()
                                conn.close()
                            except Exception as e:
                                logger.warning(f"Failed to cache threat intel for {ip}: {e}")

                except requests.exceptions.HTTPError as e:
                    if e.response.status_code == 429:
                        # Rate limit hit - return immediately with error
                        logger.warning(f"AbuseIPDB rate limit exceeded (429). Daily quota of 1,000 requests reached.")
                        return {
                            "success": False,
                            "error": "AbuseIPDB rate limit exceeded. Daily quota reached. Try again tomorrow or use cached results only.",
                            "rate_limited": True,
                            "cached_results": len(ip_to_threat_data),
                            "ips_checked_before_limit": api_calls_made
                        }
                    else:
                        logger.warning(f"HTTP error querying AbuseIPDB for {ip}: {e}")
                        continue
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Error querying AbuseIPDB for {ip}: {e}")
                    continue

            logger.info(f"Performed {len(ips_needing_lookup)} AbuseIPDB API lookups")

        # Filter for malicious IPs (above confidence threshold)
        malicious_ips = {}
        for ip, data in ip_to_threat_data.items():
            if data.get('abuse_confidence_score', 0) >= confidence_threshold:
                malicious_ips[ip] = {
                    **data,
                    'report_url': f"https://www.abuseipdb.com/check/{ip}"
                }

        # Count connections from malicious IPs
        malicious_ip_connections = Counter()
        for entry in entries_to_analyze:
            if entry.src in malicious_ips:
                malicious_ip_connections[entry.src] += 1

        # Build detailed findings
        threat_findings = []
        for ip, count in malicious_ip_connections.most_common():
            data = malicious_ips[ip]
            threat_findings.append({
                'ip': ip,
                'blocked_connections': count,
                'abuse_confidence_score': data['abuse_confidence_score'],
                'total_reports': data['total_reports'],
                'country_code': data['country_code'],
                'isp': data['isp'],
                'usage_type': data['usage_type'],
                'is_tor': data['is_tor'],
                'is_public_proxy': data['is_public_proxy'],
                'last_reported_at': data['last_reported_at'],
                'report_url': data['report_url']
            })

        return {
            "success": True,
            "summary": f"Found {len(malicious_ips)} known malicious IPs out of {len(ip_to_threat_data)} IPs checked (top 10 most frequent attackers).",
            "total_unique_ips_analyzed": len(unique_ips),
            "total_ips_checked": len(ip_to_threat_data),
            "total_connections_analyzed": len(entries_to_analyze),
            "malicious_ips_detected": len(malicious_ips),
            "threat_findings": threat_findings,
            "api_lookups_performed": len(ips_needing_lookup) if 'ips_to_check' not in locals() else len(ips_to_check),
            "cache_hits": len(ip_to_threat_data) - (len(ips_needing_lookup) if 'ips_to_check' not in locals() else len(ips_to_check)),
            "ips_skipped_due_to_limit": skipped_ips,
            "confidence_threshold": confidence_threshold
        }

    def monitor_outbound_connections(
        self,
        internal_subnets: Optional[List[str]] = None,
        common_ports: Optional[List[int]] = None,
        min_connections: int = 1
    ) -> Dict[str, Any]:
        """
        Analyzes allowed outbound traffic for anomalies that could indicate a compromise.

        This tool shifts focus from external attackers to internal threats. An infected
        internal host calling out to a malicious server is a critical security event.
        This analysis looks for internal clients using non-standard ports for outbound
        communication, which is a common tactic for malware.

        :param internal_subnets: List of internal network ranges in CIDR notation (e.g., '192.168.1.0/24')
                                 If None, uses RFC1918 private ranges
        :param common_ports: List of ports considered normal for outbound traffic
                            If None, uses standard ports (80, 443, 53, etc.)
        :param min_connections: Minimum number of connections to flag (default: 1)
        :return: Dictionary listing suspicious outbound connections
        """
        # Default to RFC1918 private address ranges if not specified
        if internal_subnets is None:
            internal_subnets = [
                '10.0.0.0/8',       # Class A private
                '172.16.0.0/12',    # Class B private
                '192.168.0.0/16',   # Class C private
            ]

        # Default common/allowed outbound ports
        if common_ports is None:
            common_ports = [
                80,    # HTTP
                443,   # HTTPS
                53,    # DNS
                123,   # NTP
                587,   # SMTP (submission)
                993,   # IMAPS
                995,   # POP3S
                465,   # SMTPS
                22,    # SSH (common for git, scp, etc.)
                21,    # FTP
                20,    # FTP data
                25,    # SMTP
                110,   # POP3
                143,   # IMAP
                3389,  # RDP (for remote work)
            ]

        # Parse internal networks for efficient checking
        try:
            internal_networks = [ipaddress.ip_network(net) for net in internal_subnets]
        except ValueError as e:
            return {
                "success": False,
                "error": f"Invalid internal subnet format: {e}"
            }

        def is_internal(ip_str: str) -> bool:
            """Check if IP is in internal network ranges."""
            if not ip_str:
                return False
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                return any(ip_obj in net for net in internal_networks)
            except ValueError:
                return False

        # Filter for allowed traffic only (action = 'pass')
        allowed_entries = self.filter_allowed()

        if not allowed_entries:
            return {
                "success": True,
                "summary": "No allowed outbound traffic found in the provided log entries.",
                "total_allowed_connections": 0,
                "suspicious_outbound_connections": 0,
                "suspicious_connections": []
            }

        # Identify outbound traffic: internal source → external destination
        outbound_connections = []
        for entry in allowed_entries:
            src_is_internal = is_internal(entry.src)
            dst_is_internal = is_internal(entry.dst)

            # Outbound = internal source, external destination
            if src_is_internal and not dst_is_internal:
                outbound_connections.append(entry)

        if not outbound_connections:
            return {
                "success": True,
                "summary": "No outbound traffic detected (internal → external).",
                "total_allowed_connections": len(allowed_entries),
                "total_outbound_connections": 0,
                "suspicious_outbound_connections": 0,
                "suspicious_connections": []
            }

        # Filter for non-standard ports
        suspicious_connections = []
        for entry in outbound_connections:
            if entry.dst_port is not None and entry.dst_port not in common_ports:
                suspicious_connections.append(entry)

        # Aggregate by source IP, destination IP, and destination port
        connection_summary = defaultdict(lambda: {
            'count': 0,
            'protocol': None,
            'first_seen': None,
            'last_seen': None
        })

        for entry in suspicious_connections:
            key = (entry.src, entry.dst, entry.dst_port)
            connection_summary[key]['count'] += 1
            connection_summary[key]['protocol'] = entry.proto or 'unknown'

            if connection_summary[key]['first_seen'] is None:
                connection_summary[key]['first_seen'] = entry.timestamp
            connection_summary[key]['last_seen'] = entry.timestamp

        # Build detailed findings
        suspicious_findings = []
        for (src_ip, dst_ip, dst_port), data in connection_summary.items():
            if data['count'] >= min_connections:
                suspicious_findings.append({
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'destination_port': dst_port,
                    'protocol': data['protocol'],
                    'connection_count': data['count'],
                    'first_seen': data['first_seen'],
                    'last_seen': data['last_seen']
                })

        # Sort by connection count (most suspicious first)
        suspicious_findings.sort(key=lambda x: x['connection_count'], reverse=True)

        # Identify unique internal hosts making suspicious connections
        unique_internal_hosts = set(finding['source_ip'] for finding in suspicious_findings)

        return {
            "success": True,
            "summary": f"Found {len(suspicious_findings)} unique suspicious outbound connections on non-standard ports from {len(unique_internal_hosts)} internal host(s).",
            "total_allowed_connections": len(allowed_entries),
            "total_outbound_connections": len(outbound_connections),
            "suspicious_outbound_connections": len(suspicious_connections),
            "unique_suspicious_flows": len(suspicious_findings),
            "unique_internal_hosts_affected": len(unique_internal_hosts),
            "suspicious_connections": suspicious_findings,
            "internal_subnets_checked": internal_subnets,
            "common_ports_excluded": common_ports
        }

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

