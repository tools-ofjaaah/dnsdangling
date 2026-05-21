"""Geração de relatórios em JSON e Markdown."""

import json
from pathlib import Path
from typing import List, Dict
from datetime import datetime


def generate_report(findings: List[Dict], target: str, output_base: str, format: str = "json"):
    """Gera relatórios nos formatos especificados."""

    if format == "json" or format == "both":
        save_json(findings, target, output_base)

    if format == "markdown" or format == "both":
        save_markdown(findings, target, output_base)


def save_json(findings: List[Dict], target: str, output_base: str):
    """Salva relatório em formato JSON."""
    report = {
        "target": target,
        "scanned_at": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": findings
    }

    output_file = f"{output_base}.json"
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def save_markdown(findings: List[Dict], target: str, output_base: str):
    """Salva relatório em formato Markdown."""

    md = f"""# DNS Dangling Scanner — Relatório

## Target: {target}
**Data do scan:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Resumo

| Métrica | Valor |
|---------|-------|
| **Total de findings** | {len(findings)} |
| **Críticos** | {sum(1 for f in findings if f.get('severity') == 'Critical')} |
| **Altos** | {sum(1 for f in findings if f.get('severity') == 'High')} |
| **Médios** | {sum(1 for f in findings if f.get('severity') == 'Medium')} |
| **Baixos** | {sum(1 for f in findings if f.get('severity') == 'Low')} |

---

"""

    if not findings:
        md += "**Nenhuma vulnerabilidade DNS Dangling encontrada.**\n"
    else:
        for i, f in enumerate(findings, 1):
            md += f"""

## Finding #{i}: {f['subdomain']}

| Campo | Valor |
|-------|------|
| **Subdomínio** | {f['subdomain']} |
| **CNAME** | {f['cname']} |
| **Serviço** | {f['service']} |
| **Severidade** | {f['severity']} |
| **CVSS Vector** | {f['cvss_vector']} |
| **HTTP Status** | {f.get('http_status', 'N/A')} |

### PoC

{f.get('poc', 'PoC não disponível')}

---
"""

    output_file = f"{output_base}.md"
    with open(output_file, "w") as f:
        f.write(md)


def load_findings(json_file: str) -> List[Dict]:
    """Carrega findings de um arquivo JSON."""
    with open(json_file) as f:
        data = json.load(f)
    return data.get("findings", [])


def print_summary(findings: List[Dict]):
    """Imprime sumário dos findings no terminal."""

    if not findings:
        print("[*] Nenhuma vulnerabilidade encontrada.")
        return

    print("\n" + "=" * 60)
    print("RESUMO DOS FINDINGS")
    print("=" * 60)

    by_severity = {"Critical": [], "High": [], "Medium": [], "Low": []}
    for f in findings:
        sev = f.get("severity", "Medium")
        if sev in by_severity:
            by_severity[sev].append(f)

    for sev in ["Critical", "High", "Medium", "Low"]:
        if by_severity[sev]:
            print(f"\n[{sev}] ({len(by_severity[sev])})")
            for f in by_severity[sev]:
                print(f"  - {f['subdomain']} -> {f['cname']} ({f['service']})")