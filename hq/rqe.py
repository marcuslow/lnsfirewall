"""
Rules Query Engine (RQE)
- Parses pfSense rules XML from the rulesets table
- Provides structured query helpers used by AI Command Center and tests

Design goals:
- Zero external dependencies (uses xml.etree.ElementTree)
- Be tolerant of schema variations (destinationport vs dstport, etc.)
- Support offline/local analysis directly from the SQLite DB
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
import aiosqlite

# Common service -> (port, protocol)
SERVICE_PORTS = {
    "ssh": (22, "tcp"),
    "http": (80, "tcp"),
    "https": (443, "tcp"),
    "ftp": (21, "tcp"),  # control; note: data often 20
}


def _safe_text(elem: Optional[ET.Element]) -> str:
    return (elem.text or "").strip() if elem is not None else ""


def _first_child_text(parent: Optional[ET.Element], *names: str) -> str:
    if parent is None:
        return ""
    for n in names:
        c = parent.find(n)
        if c is not None and (c.text or "").strip():
            return (c.text or "").strip()
    return ""


def _find_port(parent: Optional[ET.Element]) -> Optional[int]:
    """Extract a port from varied tag names under a node."""
    if parent is None:
        return None
    # direct port element
    port = _first_child_text(parent, "port", "destinationport", "dstport", "local-port", "sourceport", "srcport")
    if port:
        try:
            return int(port)
        except ValueError:
            pass
    # If parent itself is a port-like tag
    if parent.tag.lower().endswith("port"):
        try:
            return int(_safe_text(parent))
        except ValueError:
            pass
    # Search any child containing 'port' in name
    for child in parent:
        if "port" in child.tag.lower():
            try:
                return int(_safe_text(child))
            except ValueError:
                continue
    return None


def _find_addr(parent: Optional[ET.Element]) -> str:
    if parent is None:
        return ""
    # preferred explicit address
    addr = _first_child_text(parent, "address", "network", "host")
    if addr:
        return addr
    # special markers
    if parent.find("any") is not None:
        return "any"
    if parent.find("lan") is not None:
        return "lan"
    if parent.find("wan") is not None:
        return "wan"
    # fallback to text
    t = _safe_text(parent)
    return t


@dataclass
class NatRule:
    descr: str = ""
    interface: str = ""
    protocol: str = ""
    src_addr: str = ""
    src_port: Optional[int] = None
    dst_addr: str = ""
    dst_port: Optional[int] = None
    target: str = ""  # internal host
    local_port: Optional[int] = None


@dataclass
class FilterRule:
    descr: str = ""
    interface: str = ""
    action: str = ""  # pass/block/reject
    protocol: str = ""
    src_addr: str = ""
    src_port: Optional[int] = None
    dst_addr: str = ""
    dst_port: Optional[int] = None
    disabled: bool = False


class RulesQueryEngine:
    def __init__(self, rules_xml: str):
        self.rules_xml = rules_xml
        self.nat_rules: List[NatRule] = []
        self.filter_rules: List[FilterRule] = []
        self._parse()

    @staticmethod
    async def load_latest_rules_xml(db_path: str, client_id_or_name: str) -> Optional[Tuple[str, str]]:
        """Return (rules_xml, ruleset_id) for latest rules of client; supports id or name.
        If the client cannot be resolved, fall back to the latest ruleset across all clients.
        """
        async with aiosqlite.connect(db_path) as db:
            # Resolve client id
            actual_id = client_id_or_name
            try:
                cur = await db.execute("SELECT id, client_name FROM clients")
                rows = await cur.fetchall()
                m = {r[0]: r[1] for r in rows}
                if client_id_or_name not in m:
                    # search by name
                    for cid, name in m.items():
                        if name == client_id_or_name:
                            actual_id = cid
                            break
            except Exception:
                pass

            cur = await db.execute(
                """
                SELECT rules_xml, id
                FROM rulesets
                WHERE client_id = ?
                ORDER BY ingested_at DESC
                LIMIT 1
                """,
                (actual_id,),
            )
            row = await cur.fetchone()
            if row:
                return row[0], row[1]
            # Fallback: latest ruleset regardless of client
            cur = await db.execute(
                """
                SELECT rules_xml, id
                FROM rulesets
                ORDER BY ingested_at DESC
                LIMIT 1
                """
            )
            row = await cur.fetchone()
            if not row:
                return None
            return row[0], row[1]

    def _parse(self) -> None:
        try:
            root = ET.fromstring(self.rules_xml)
        except ET.ParseError:
            # Try wrapping in synthetic root to handle concatenated fragments
            try:
                wrapped = f"<wrapper>{self.rules_xml}</wrapper>"
                root = ET.fromstring(wrapped)
            except ET.ParseError:
                return
        # Find sections (be tolerant to nesting)
        nat_nodes = root.findall('.//nat')
        filter_nodes = root.findall('.//filter')
        # NAT rules
        for nat in nat_nodes:
            for r in nat.findall('.//rule'):
                self.nat_rules.append(self._parse_nat_rule(r))
        # Filter rules
        for flt in filter_nodes:
            for r in flt.findall('.//rule'):
                self.filter_rules.append(self._parse_filter_rule(r))
        # Fallback: if no explicit containers, treat any <rule> as filter rule
        if not self.nat_rules and not self.filter_rules:
            # Include root if it's a single <rule>
            if root.tag.lower() == 'rule':
                self.filter_rules.append(self._parse_filter_rule(root))
            for r in root.findall('.//rule'):
                self.filter_rules.append(self._parse_filter_rule(r))

    def _parse_nat_rule(self, r: ET.Element) -> NatRule:
        descr = _first_child_text(r, 'descr')
        interface = _first_child_text(r, 'interface')
        protocol = _first_child_text(r, 'protocol') or 'any'
        source = r.find('source')
        dest = r.find('destination')
        src_addr = _find_addr(source)
        dst_addr = _find_addr(dest)
        # Ports
        src_port = _find_port(source)
        dst_port = _find_port(dest)
        # PFsense uses <target> and <local-port> for redirection
        target = _first_child_text(r, 'target')
        local_port = None
        lp = _first_child_text(r, 'local-port')
        if lp:
            try:
                local_port = int(lp)
            except ValueError:
                pass
        return NatRule(
            descr=descr,
            interface=interface,
            protocol=protocol.lower(),
            src_addr=src_addr,
            src_port=src_port,
            dst_addr=dst_addr,
            dst_port=dst_port,
            target=target,
            local_port=local_port,
        )

    def _parse_filter_rule(self, r: ET.Element) -> FilterRule:
        descr = _first_child_text(r, 'descr')
        interface = _first_child_text(r, 'interface')
        # action/type may be present as <type>pass</type> or <action>block</action>
        action = _first_child_text(r, 'action', 'type') or 'pass'
        protocol = _first_child_text(r, 'protocol') or 'any'
        disabled = r.find('disabled') is not None
        source = r.find('source')
        dest = r.find('destination')
        src_addr = _find_addr(source)
        dst_addr = _find_addr(dest)
        src_port = _find_port(source)
        dst_port = _find_port(dest)
        # Also check top-level destinationport/dstport
        if dst_port is None:
            try:
                dp = _first_child_text(r, 'destinationport', 'dstport')
                if dp:
                    dst_port = int(dp)
            except ValueError:
                pass
        return FilterRule(
            descr=descr,
            interface=interface,
            action=action.lower(),
            protocol=protocol.lower(),
            src_addr=src_addr,
            src_port=src_port,
            dst_addr=dst_addr,
            dst_port=dst_port,
            disabled=disabled,
        )

    # Query helpers
    def list_port_forwarding(self) -> List[NatRule]:
        """Return NAT rules that look like port forwards (target/local_port set or dst_port present)."""
        out = []
        for r in self.nat_rules:
            if r.target or r.local_port or r.dst_port is not None:
                out.append(r)
        return out

    def find_rules_by_port(self, port: int) -> Dict[str, List[Dict[str, Any]]]:
        nat_matches: List[Dict[str, Any]] = []
        flt_matches: List[Dict[str, Any]] = []
        for r in self.nat_rules:
            if r.dst_port == port or r.local_port == port or r.src_port == port:
                nat_matches.append(self._nat_to_dict(r))
        for r in self.filter_rules:
            if r.dst_port == port or r.src_port == port:
                flt_matches.append(self._filter_to_dict(r))
        return {"nat": nat_matches, "filter": flt_matches}

    def find_rules_by_service(self, service: str) -> Dict[str, List[Dict[str, Any]]]:
        svc = service.lower().strip()
        port_proto = SERVICE_PORTS.get(svc)
        if not port_proto:
            return {"nat": [], "filter": []}
        port, proto = port_proto
        matches = self.find_rules_by_port(port)
        # Optionally filter by protocol if present
        matches["nat"] = [m for m in matches["nat"] if (m.get("protocol") in (proto, "any", ""))]
        matches["filter"] = [m for m in matches["filter"] if (m.get("protocol") in (proto, "any", ""))]
        return matches

    def find_blocking_rules(self) -> List[Dict[str, Any]]:
        return [self._filter_to_dict(r) for r in self.filter_rules if r.action in ("block", "reject")]

    def find_allowed_rules(self) -> List[Dict[str, Any]]:
        return [self._filter_to_dict(r) for r in self.filter_rules if r.action == "pass"]

    def find_rules_with_ip(self, ip_fragment: str) -> List[Dict[str, Any]]:
        ip_fragment = ip_fragment.strip().lower()
        out: List[Dict[str, Any]] = []
        for r in self.nat_rules:
            if ip_fragment in (r.src_addr or "").lower() or ip_fragment in (r.dst_addr or "").lower() or ip_fragment in (r.target or "").lower():
                out.append(self._nat_to_dict(r))
        for r in self.filter_rules:
            if ip_fragment in (r.src_addr or "").lower() or ip_fragment in (r.dst_addr or "").lower():
                out.append(self._filter_to_dict(r))
        return out

    def summarize(self) -> Dict[str, Any]:
        return {
            "nat_rules": len(self.nat_rules),
            "filter_rules": len(self.filter_rules),
            "port_forwards": len(self.list_port_forwarding()),
        }

    # Serialization helpers
    def _nat_to_dict(self, r: NatRule) -> Dict[str, Any]:
        return {
            "type": "nat",
            "descr": r.descr,
            "interface": r.interface,
            "protocol": r.protocol,
            "src_addr": r.src_addr,
            "src_port": r.src_port,
            "dst_addr": r.dst_addr,
            "dst_port": r.dst_port,
            "target": r.target,
            "local_port": r.local_port,
        }

    def _filter_to_dict(self, r: FilterRule) -> Dict[str, Any]:
        return {
            "type": "filter",
            "descr": r.descr,
            "interface": r.interface,
            "action": r.action,
            "protocol": r.protocol,
            "src_addr": r.src_addr,
            "src_port": r.src_port,
            "dst_addr": r.dst_addr,
            "dst_port": r.dst_port,
            "disabled": r.disabled,
        }

