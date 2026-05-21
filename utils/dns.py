"""Utilitários DNS: resolvers, queries e trace de CNAME chain."""

import dns.resolver
import dns.rdatatype
from typing import List, Optional, Tuple


def resolve_a(domain: str) -> List[str]:
    """Resolve registros A para um domínio."""
    ips = []
    try:
        answers = dns.resolver.resolve(domain, "A")
        ips = [str(r.address) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        pass
    except Exception:
        pass
    return ips


def resolve_cname(domain: str) -> Optional[str]:
    """Resolve registro CNAME e retorna o target ou None."""
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        return str(answers[0].target).rstrip(".")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None
    except Exception:
        return None


def trace_cname_chain(domain: str, max_depth: int = 10) -> List[str]:
    """Segue o chain de CNAME até o final ou max_depth."""
    chain = []
    current = domain
    visited = set()

    for _ in range(max_depth):
        if current in visited:
            break
        visited.add(current)

        cname = resolve_cname(current)
        if not cname:
            break

        chain.append(cname)
        current = cname

    return chain


def get_dns_trace(domain: str) -> dict:
    """Retorna um trace DNS completo para um domínio."""
    result = {
        "domain": domain,
        "a_records": [],
        "cname_chain": [],
        "mx_records": [],
        "txt_records": [],
        "ns_records": []
    }

    result["a_records"] = resolve_a(domain)

    cname = resolve_cname(domain)
    if cname:
        result["cname_chain"] = [cname] + trace_cname_chain(cname)

    try:
        mx = dns.resolver.resolve(domain, "MX")
        result["mx_records"] = [str(r.exchange).rstrip(".") for r in mx]
    except Exception:
        pass

    try:
        txt = dns.resolver.resolve(domain, "TXT")
        result["txt_records"] = [str(r.strings[0].decode()) if r.strings else "" for r in txt]
    except Exception:
        pass

    try:
        ns = dns.resolver.resolve(domain, "NS")
        result["ns_records"] = [str(r).rstrip(".") for r in ns]
    except Exception:
        pass

    return result


def check_zone_transfer(domain: str) -> List[str]:
    """Tenta zone transfer e retorna registros encontrados."""
    records = []
    ns_records = []

    try:
        ns = dns.resolver.resolve(domain, "NS")
        ns_records = [str(r).rstrip(".") for r in ns]
    except Exception:
        return records

    for ns_server in ns_records:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain, timeout=5))
            for name, node in zone.items():
                for rdataset in node.rdatasets:
                    if rdataset.rdtype == dns.rdatatype.A:
                        record = f"{name} A {' '.join([str(r.address) for r in rdataset])}"
                        records.append(record)
                    elif rdataset.rdtype == dns.rdatatype.CNAME:
                        record = f"{name} CNAME {' '.join([str(r) for r in rdataset])}"
                        records.append(record)
        except Exception:
            continue

    return records