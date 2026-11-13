"""Address classification and small naming helpers shared by analysis stages."""

from __future__ import annotations

import ipaddress
from functools import lru_cache

_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "100.64.0.0/10",                                    # RFC 6598 carrier-grade NAT
    "169.254.0.0/16",                                   # IPv4 link-local
    "fc00::/7",                                         # IPv6 unique local
    "fe80::/10",                                        # IPv6 link-local
)]

INTERNAL, EXTERNAL, MULTICAST, BROADCAST, LOOPBACK, OTHER = (
    "internal", "external", "multicast", "broadcast", "loopback", "other")


class AddressClassifier:
    """Decide whether an address belongs to the monitored network.

    Documentation ranges (192.0.2.0/24 etc.) are deliberately treated as
    external: they stand in for public addresses in lab captures.
    """

    def __init__(self, extra_internal: tuple[str, ...] = ()):
        self._nets = list(_INTERNAL)
        for n in extra_internal:
            try:
                self._nets.append(ipaddress.ip_network(n, strict=False))
            except ValueError:
                continue
        self._cache: dict[str, str] = {}

    def scope(self, ip: str | None) -> str:
        if not ip:
            return OTHER
        s = self._cache.get(ip)
        if s is None:
            if len(self._cache) > 500_000:
                self._cache.clear()
            s = self._cache[ip] = self._classify(ip)
        return s

    def is_internal(self, ip: str | None) -> bool:
        return self.scope(ip) == INTERNAL

    def is_external(self, ip: str | None) -> bool:
        return self.scope(ip) == EXTERNAL

    def _classify(self, ip: str) -> str:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return OTHER
        if a.is_multicast:
            return MULTICAST
        if a.version == 4 and (int(a) == 0xFFFFFFFF):
            return BROADCAST
        if a.is_loopback:
            return LOOPBACK
        if a.is_unspecified:
            return OTHER
        for net in self._nets:
            if a.version == net.version and a in net:
                # x.x.x.255 inside RFC 1918 space is almost always a
                # directed broadcast address
                if a.version == 4 and (int(a) & 0xFF) == 0xFF:
                    return BROADCAST
                return INTERNAL
        return EXTERNAL


# Second-level public suffixes that are common enough to matter when grouping
# DNS names by registered domain. This is a pragmatic subset, not the full
# Public Suffix List (see docs/ARCHITECTURE.md, "Known limitations").
_MULTI_SUFFIX = frozenset((
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "net.nz", "co.jp", "ne.jp", "or.jp", "ac.jp",
    "co.kr", "or.kr", "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "com.tw", "com.hk",
    "co.in", "net.in", "org.in", "com.mx", "com.ar", "com.tr",
    "co.za", "org.za", "com.sg", "com.my", "co.id", "co.il",
    "com.ru", "com.ua", "com.pl", "com.eg", "com.sa", "co.th",
))


@lru_cache(maxsize=100_000)
def registered_domain(name: str) -> str:
    """Best-effort eTLD+1 for a DNS name ('a.b.example.co.uk' -> 'example.co.uk')."""
    name = name.rstrip(".").lower()
    labels = name.split(".")
    if len(labels) <= 2:
        return name
    last2 = ".".join(labels[-2:])
    if last2 in _MULTI_SUFFIX and len(labels) >= 3:
        return ".".join(labels[-3:])
    if name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa"):
        return ".".join(labels[-2:])
    return last2


TCP_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "TLS", 445: "SMB",
    465: "SMTPS", 587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM",
    6379: "Redis", 8080: "HTTP-alt", 8443: "TLS-alt", 9200: "Elasticsearch",
    27017: "MongoDB",
}
UDP_SERVICES = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP", 137: "NBNS",
    138: "NetBIOS", 161: "SNMP", 162: "SNMP", 443: "QUIC", 500: "IKE",
    514: "Syslog", 1900: "SSDP", 3478: "STUN", 4500: "IPsec", 5353: "mDNS",
    5355: "LLMNR",
}


def service_name(proto: str, port: int | None) -> str:
    if port is None:
        return ""
    table = TCP_SERVICES if proto == "TCP" else UDP_SERVICES if proto == "UDP" else {}
    return table.get(port, "")
