"""Geração de PoC para DNS Dangling."""

import time
from typing import Dict


def generate_poc(subdomain: str, cname: str, service: str, validation: Dict) -> str:
    """Gera PoC estruturado em Markdown."""

    http_status = validation.get("http_status", 0)
    http_evidence = validation.get("http_evidence", "")

    severity = validation.get("severity", "Medium")
    cvss_vector = validation.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")

    cvss_score = calculate_cvss_score(cvss_vector)

    poc = f"""
## PoC — DNS Dangling (Subdomain Takeover)

### Informações Gerais
- **Domínio afetado:** {subdomain}
- **Registro DNS:** CNAME
- **Valor CNAME:** {cname}
- **Serviço cloud:** {service}

### Evidência DNS
```bash
dig CNAME {subdomain}
# CNAME: {cname}
```

### Evidência HTTP
```bash
curl -I http://{cname}
# HTTP Status: {http_status}
```

**Response Body (snippet):**
```
{http_evidence[:300]}
```

### Impacto
O subdomínio {subdomain} está apontando para um recurso {service} que foi deletado ou nunca existiu.
Um atacante pode reivindicar este CNAME e:
- Hospedar phishing pages fingindo ser o domínio principal
- Servir malware ou conteúdo malicioso
- Obter certificados TLS para o subdomínio (via Let's Encrypt/DV)
- Explorar a confiança de usuários e ferramentas que usam este subdomínio

### Classificação de Severidade

| Métrica | Valor |
|---------|-------|
| **CVSS Score** | {cvss_score} |
| **CVSS Vector** | {cvss_vector} |
| **Severity** | {severity} |

### Passos para Reproduzir
1. Consultar registro DNS: `dig CNAME {subdomain}`
2. Observar que resolve para: `{cname}`
3. Fazer requisição HTTP: `curl -I http://{cname}`
4. Observar resposta mostrando que o recurso não existe

### Timeline (Bug Bounty)
- **Discovery:** {time.strftime('%Y-%m-%d')}
- **Service:** {service}
- **Status:** Vulnerável (recurso órfão)
"""

    return poc.strip()


def calculate_cvss_score(vector: str) -> float:
    """Calcula CVSS score aproximado baseado no vector."""
    base_scores = {
        "Critical": 9.0,
        "High": 8.0,
        "Medium": 5.0,
        "Low": 3.0
    }

    for severity, score in base_scores.items():
        if severity in vector:
            return score

    return 5.0


def extract_severity_from_vector(vector: str) -> str:
    """Extrai severity do CVSS vector."""
    if "CR" in vector or "Critical" in vector:
        return "Critical"
    elif "H" in vector or "High" in vector:
        return "High"
    elif "M" in vector or "Medium" in vector:
        return "Medium"
    return "Low"