"""Enumeração de subdomínios via subfinder + CRT passiva + fallback bruteforce."""

import subprocess
import re
import urllib.request
import json
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
    Enumera subdomínios usando múltiplas fontes:
    1. CRT (Certificate Transparency) - passivo
    2. subfinder (se disponível)
    3. fallback bruteforce DNS com wordlist
    """
    subdomains = []

    # 1. Passiva via CRT
    subdomains = crt_enum(domain)

    # 2. subfinder
    if not subdomains and check_subfinder():
        subdomains = subfinder_enum(domain)

    # 3. Bruteforce fallback
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
    """Fallback: bruteforce DNS com wordlist (parallel threads)."""
    import dns.resolver
    from concurrent.futures import ThreadPoolExecutor, as_completed

    subs = []
    wl_path = Path(wordlist)

    if not wl_path.exists():
        print(f"[ERROR] Wordlist não encontrada: {wordlist}")
        return subs

    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.0
    resolver.lifetime = 2.0

    with open(wl_path) as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    def check_word(word: str) -> Optional[str]:
        subdomain = f"{word}.{domain}"
        try:
            resolver.resolve(subdomain)
            return subdomain
        except dns.resolver.NXDOMAIN:
            return None
        except Exception:
            return None

    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_word, w): w for w in words}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subs.append(result)
    except Exception as e:
        print(f"[ERROR] bruteforce_enum: {e}")

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


def crt_enum(domain: str) -> List[str]:
    """
    Enumeração passiva via Certificate Transparency logs (crt.sh).
    Retorna subdomínios únicos encontrados.
    """
    subs = []
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; dnsdangle/1.0)"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name.endswith(f".{domain}") and name != domain:
                        subs.append(name)
    except Exception as e:
        print(f"[WARN] crt.sh error: {e}")

    return list(set(subs))