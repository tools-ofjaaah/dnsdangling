"""Enumeração de subdomínios via subfinder + fallback bruteforce."""

import subprocess
import re
from typing import List, Optional
from pathlib import Path


def check_subfinder() -> bool:
    """Verifica se subfinder está instalado."""
    try:
        subprocess.run(["subfinder", "-version"], capture_output=True, check=True,
                       timeout=5)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def enumerate_subdomains(domain: str, wordlist: Optional[str] = None) -> List[str]:
    """
    Enumera subdomínios usando subfinder.
    Fallback para bruteforce DNS se subfinder não estiver disponível ou falhar.
    """
    subdomains = []

    if check_subfinder():
        subdomains = subfinder_enum(domain)

    if not subdomains and wordlist:
        subdomains = bruteforce_enum(domain, wordlist)

    return list(set(subdomains))


def subfinder_enum(domain: str) -> List[str]:
    """Executa subfinder e retorna lista de subdomínios."""
    try:
        result = subprocess.run(
            ["sh", "-c", f"subfinder -d {domain} -silent -r 5 -t 10"],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0 and result.stdout.strip():
            subs = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            return subs
    except subprocess.TimeoutExpired:
        print("[WARN] subfinder timeout (60s), usando fallback bruteforce")
    except Exception as e:
        print(f"[WARN] subfinder error: {e}, usando fallback bruteforce")
    return []


def bruteforce_enum(domain: str, wordlist: str) -> List[str]:
    """Fallback: bruteforce DNS com wordlist."""
    import dns.resolver

    subs = []
    wl_path = Path(wordlist)

    if not wl_path.exists():
        print(f"[ERROR] Wordlist não encontrada: {wordlist}")
        return subs

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    try:
        base_ip = resolver.resolve(domain).address
    except Exception:
        base_ip = None

    with open(wl_path) as f:
        for line in f:
            word = line.strip()
            if not word or word.startswith("#"):
                continue

            subdomain = f"{word}.{domain}"
            try:
                resolver.resolve(subdomain)
                subs.append(subdomain)
            except dns.resolver.NXDOMAIN:
                continue
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.Timeout:
                continue
            except Exception:
                continue

    return subs


def resolve_domain(subdomain: str) -> Optional[str]:
    """Resolve um domínio e retorna o IP ou None."""
    import dns.resolver
    try:
        answers = dns.resolver.resolve(subdomain, "A")
        return str(answers[0].address)
    except Exception:
        return None


def get_cname(subdomain: str) -> Optional[str]:
    """Obtém o registro CNAME de um subdomínio."""
    import dns.resolver
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        return str(answers[0].target).rstrip(".")
    except dns.resolver.NoAnswer:
        return None
    except Exception:
        return None