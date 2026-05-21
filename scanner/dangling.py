"""Detecção de DNS Dangling via análise de CNAME e validação HTTP."""

import re
import asyncio
import aiohttp
from typing import List, Dict, Optional, Tuple
import yaml
from pathlib import Path

from scanner.poc import generate_poc


class DanglingSignature:
    """Assinatura para detecção de recurso cloud órfão."""

    def __init__(self, name: str, cname_pattern: str, http_status_expect: List[int],
                 http_body_expect: List[str], severity: str, cvss_vector: str):
        self.name = name
        self.cname_pattern = re.compile(cname_pattern)
        self.http_status_expect = http_status_expect
        self.http_body_expect = http_body_expect
        self.severity = severity
        self.cvss_vector = cvss_vector

    def matches(self, cname: str) -> bool:
        return bool(self.cname_pattern.match(cname))


def load_signatures() -> List[DanglingSignature]:
    """Carrega assinaturas do arquivo YAML."""
    sig_file = Path(__file__).parent.parent / "config" / "signatures.yaml"
    signatures = []

    if sig_file.exists():
        with open(sig_file) as f:
            data = yaml.safe_load(f)
            for sig in data.get("signatures", []):
                signatures.append(DanglingSignature(
                    name=sig["name"],
                    cname_pattern=sig["cname_pattern"],
                    http_status_expect=sig.get("http_status_expect", []),
                    http_body_expect=sig.get("http_body_expect", []),
                    severity=sig.get("severity", "Medium"),
                    cvss_vector=sig.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
                ))

    return signatures


SIGNATURES = load_signatures()


async def check_http(session: aiohttp.ClientSession, url: str) -> Tuple[int, str]:
    """Faz requisição HTTP e retorna status code + body snippet."""
    try:
        async with session.head(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            body = ""
            if resp.content_length and resp.content_length < 10240:
                body = await resp.text()
            return resp.status, body[:500]
    except asyncio.TimeoutError:
        return 0, "TIMEOUT"
    except Exception as e:
        return 0, str(e)[:100]


async def validate_dangling(session: aiohttp.ClientSession, cname: str, subdomain: str) -> Optional[Dict]:
    """Valida se um CNAME aponta para recurso órfão."""
    for sig in SIGNATURES:
        if sig.matches(cname):
            try:
                async with session.head(f"http://{cname}", allow_redirects=True,
                                        timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    body = ""
                    if resp.content_length and resp.content_length < 10240:
                        body = await resp.text()

                    status = resp.status
                    body_lower = body.lower()

                    status_match = not sig.http_status_expect or status in sig.http_status_expect
                    body_match = not sig.http_body_expect or any(
                        pattern.lower() in body_lower for pattern in sig.http_body_expect
                    )

                    if status_match and body_match:
                        return {
                            "signature": sig.name,
                            "severity": sig.severity,
                            "cvss_vector": sig.cvss_vector,
                            "http_status": status,
                            "http_evidence": body[:200] if body else ""
                        }
            except Exception:
                continue
    return None


async def scan_subdomain(session: aiohttp.ClientSession, subdomain: str) -> Optional[Dict]:
    """Escaneia um subdomínio para detectar DNS Dangling."""
    import dns.resolver

    try:
        cname = None
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0

        try:
            answers = resolver.resolve(subdomain, "CNAME")
            cname = str(answers[0].target).rstrip(".")
        except dns.resolver.NoAnswer:
            return None
        except Exception:
            return None

        if not cname:
            return None

        for sig in SIGNATURES:
            if sig.matches(cname):
                validation = await validate_dangling(session, cname, subdomain)
                if validation:
                    return {
                        "subdomain": subdomain,
                        "cname": cname,
                        "service": sig.name,
                        "vulnerable": True,
                        "severity": validation["severity"],
                        "cvss_vector": validation["cvss_vector"],
                        "http_status": validation["http_status"],
                        "http_evidence": validation["http_evidence"],
                        "poc": generate_poc(subdomain, cname, sig.name, validation)
                    }

    except Exception:
        pass

    return None


async def scan_dangling(subdomains: List[str], max_concurrency: int = 50) -> List[Dict]:
    """Escaneia múltiplos subdomínios em paralelo com controle de concorrência."""
    findings = []
    semaphore = asyncio.Semaphore(max_concurrency)

    async def bounded_scan(session: aiohttp.ClientSession, subdomain: str) -> Optional[Dict]:
        async with semaphore:
            return await scan_subdomain(session, subdomain)

    async with aiohttp.ClientSession() as session:
        tasks = [bounded_scan(session, sub) for sub in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result:
                findings.append(result)

    return findings