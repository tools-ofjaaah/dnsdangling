# DNS Dangling Scanner

```
╔═══════════════════════════════════════════════════════════════════╗
║        OFJAAAH TAKEOVER - DNS DANGLING SCANNER v2.0         ║
║        Auto-Detect + Auto-Exploit + Index Page              ║
╚═══════════════════════════════════════════════════════════════════╝
```

## Overview

**dnsdangle** is a DNS Dangling Scanner that detects and exploits Subdomain Takeover vulnerabilities.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run a scan
python3 dnsdangle_exploit.py target.com

# Get help
python3 dnsdangle_exploit.py --help
```

## Features

- Auto-Detection of dangling DNS records
- Auto-Exploitation of vulnerable subdomains
- Support for AWS S3, Azure, GitHub Pages, Heroku, and more
- JSON output for integration
- Beautiful terminal output with colors