# Phantom Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109.0-009688.svg)](https://fastapi.tiangolo.com)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](https://github.com/Kuduxaaa/phantom)

> **A modern, extensible security testing framework for bug bounty hunters and penetration testers.**

Phantom is a comprehensive reconnaissance and vulnerability assessment platform designed to streamline the bug bounty workflow. Built with modern async Python, it provides a unified interface for asset discovery, vulnerability detection, and intelligence gathering.

---

## Quick Start

```bash
cd backend
pip install -r requirements.txt

# Scan a target with all 26 templates
python scan.py http://target.com

# Filter by category or severity
python scan.py http://target.com -t injection/sql
python scan.py http://target.com --severity high --tags sqli,xss

# Tune HTTP and crawler behaviour
python scan.py http://target.com -c 20 -d 5 --max-pages 100
python scan.py http://target.com -H "Authorization: Bearer TOKEN" --proxy http://127.0.0.1:8080

# Multi-target scan with JSON output
python scan.py -l targets.txt -o results.json --silent

# Utilities
python scan.py --list          # List all templates
python scan.py --validate      # Validate templates
python scan.py --version
```

---

## Features

### Scanner CLI

A standalone CLI scanner (`scan.py`) inspired by Nuclei and sqlmap:

| Group | Flags | Purpose |
|-------|-------|---------|
| **Target** | `<url>`, `-l FILE` | Single URL or file with one URL per line |
| **Templates** | `-t`, `--tags`, `--severity`, `--list`, `--validate` | Filter, browse, and validate templates |
| **Crawler** | `-d`, `--max-pages`, `--no-crawl` | Automatic parameter and form discovery |
| **HTTP** | `-c`, `--timeout`, `-H`, `--proxy`, `--follow-redirects` | Concurrency, headers, proxy, redirects |
| **Output** | `-o FILE`, `--silent`, `--version` | JSON export, quiet mode |

Key capabilities:
- **Automatic crawling** discovers injectable parameters and forms before scanning
- **Template filtering** by path, severity level, or tags
- **Multi-target** scans from a URL list file
- **Silent mode** suppresses INFO logs, showing only vulnerabilities
- **JSON output** with full vulnerability details, statistics, and affected endpoints
- **Connection validation** with early abort and HTTPS fallback suggestion on failure
- **Proxy support** for routing through Burp Suite or similar tools

### Asset Management
- **Vault System**: Organize targets by bug bounty program
- **Hierarchical Structure**: Domain -> Subdomain -> Endpoint relationships
- **Scope Validation**: Automatic in-scope/out-of-scope checking
- **Asset Intelligence**: Track technologies, services, and metadata

### Reconnaissance Engine
- **Subdomain Enumeration**: Passive and active discovery methods
- **DNS Analysis**: Comprehensive record enumeration and resolution
- **Port Scanning**: Service detection and banner grabbing
- **Technology Detection**: Identify frameworks, libraries, and infrastructure

### Vulnerability Assessment
- **Signature System**: YAML-based detection templates (inspired by Nuclei)
- **Custom Scanner Engine**: Extensible vulnerability detection
- **Multi-step Testing**: Chain requests with data extraction
- **Payload Attacks**: Batteringram, Pitchfork, and Clusterbomb modes
- **False Positive Suppression**: Multi-layer matchers with negative filters

### Intelligence & Analysis
- **JavaScript Analysis**: Endpoint extraction and secret detection
- **API Discovery**: REST, GraphQL, and WebSocket enumeration
- **Network Traffic**: Request/response capture and analysis
- **Finding Management**: Track, triage, and report vulnerabilities

---

## Architecture

```
phantom-framework/
├── backend/
│   ├── scan.py                    # CLI scanner entry point
│   ├── app/
│   │   ├── api/                   # FastAPI REST endpoints
│   │   ├── core/
│   │   │   ├── scanners/          # HTTPClient, SignatureScanner, Crawler
│   │   │   └── signatures/        # Parser, matchers, DSL engine
│   │   ├── models/                # SQLAlchemy models
│   │   ├── repositories/          # Data access layer
│   │   └── services/              # Business logic
│   └── templates/                 # 26 detection templates
│       ├── exposure/              # Credential & error disclosure
│       ├── fuzzing/               # Parameter fuzzing (SQLi, XSS, SSRF, ...)
│       ├── injection/             # SQL, XSS, SSTI, XXE, CRLF, Command
│       ├── misconfiguration/      # 403 bypass
│       ├── redirect/              # Open redirect, host header injection
│       └── ssrf/                  # SSRF detection
└── tests/
```

**Technology Stack:**
- **Backend**: FastAPI, SQLAlchemy, AsyncIO
- **Database**: MySQL (async via aiomysql)
- **Scanning**: httpx (async HTTP), custom crawler
- **Templates**: YAML signature system with DSL support

---

## Signature System

Phantom uses a declarative YAML-based [signature system](https://github.com/Kuduxaaa/phantom-framework/blob/main/docs/Template_Development_Guide.md) for vulnerability detection:

```yaml
id: sql-injection-check
name: SQL Injection Detection
severity: critical

metadata:
  cwe: CWE-89
  owasp: A03:2021

requests:
  - method: GET
    path:
      - "/api/users?id={{payload}}"

    attack: batteringram
    payloads:
      payload:
        - "1'"
        - '1"'

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: regex
        regex:
          - "SQL syntax.*MySQL"
          - "Warning.*mysqli"
        condition: or

      # Reject false positives from WAF block pages
      - type: word
        negative: true
        words:
          - "Request Blocked"

    extractors:
      - type: regex
        name: error_message
        regex:
          - "(SQL syntax[^<]+)"
```

**Features:**
- Multi-step request chains with variable extraction
- Variable templating with DSL functions
- Advanced payload fuzzing (Batteringram, Pitchfork, Clusterbomb)
- Response matching (word, regex, status, size, binary, DSL)
- Negative matchers for false positive suppression
- Data extraction (regex, JSON, XPath, KVal, DSL)
- `stop-at-first-match` for scan efficiency

See [Template Development Guide](https://github.com/Kuduxaaa/phantom-framework/blob/main/docs/Template_Development_Guide.md) for detailed documentation.

---

## Roadmap

### Phase 1: Foundation (Current)
- [x] Core architecture and data models
- [x] Signature parser and validator
- [x] HTTP scanner with DSL support
- [x] Multi-step request chains
- [x] CLI scanner with argument groups and output formatting
- [x] Web crawler with parameter and form discovery
- [x] Template filtering by severity, tags, and path
- [x] Multi-target scanning and JSON export
- [x] HTTP proxy and custom header support
- [ ] Database integration
- [ ] REST API endpoints

### Phase 2: Reconnaissance
- [ ] Subdomain enumeration (passive sources)
- [ ] DNS resolution and analysis
- [ ] Port scanning integration
- [ ] Technology fingerprinting
- [ ] Web crawling with Playwright

### Phase 3: Intelligence
- [ ] JavaScript analysis and secret detection
- [ ] API endpoint discovery
- [ ] Parameter mining
- [ ] Network traffic analysis
- [ ] Asset relationship mapping

### Phase 4: Advanced Features
- [ ] Workflow automation
- [ ] Scheduled scanning
- [ ] Change detection and monitoring
- [ ] Report generation
- [ ] WebSocket real-time updates
- [ ] Phantom Proxy (Requests capturing/replying/fuzzing)
- [ ] Built-in AI agent assistant

### Phase 5: UI & Visualization
- [ ] Vue 3 frontend
- [ ] Interactive dashboards
- [ ] Asset relationship graphs
- [ ] Finding management interface

---

## Contributing

Contributions are welcome! This project is in early development, and we're building the foundation together.

**Ways to contribute:**
- Report bugs and request features via Issues
- Submit pull requests for bug fixes or new features
- Improve documentation
- Share detection templates
- Test on different environments

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

**For Educational and Authorized Testing Only**

This tool is designed for security professionals, penetration testers, and bug bounty hunters conducting authorized security assessments. Users are solely responsible for complying with applicable laws and regulations.

**Usage Rules:**
- Only test systems you own or have explicit permission to test
- Respect bug bounty program rules and scope
- Never use for malicious purposes
- Always practice responsible disclosure

The authors and contributors are not responsible for misuse or damage caused by this tool.

---

## Contact

- **Issues**: [GitHub Issues](https://github.com/Kuduxaaa/phantom-framework/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Kuduxaaa/phantom-framework/discussions)

---

## Acknowledgments

Inspired by industry-leading tools:
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Template system design
- [Amass](https://github.com/owasp-amass/amass) - Asset discovery methodology
- [Burp Suite](https://portswigger.net/burp) - Attack pattern concepts

Built with amazing open-source technologies:
- [FastAPI](https://fastapi.tiangolo.com/) - Modern web framework
- [Playwright](https://playwright.dev/) - Browser automation
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM
- [PyYAML](https://pyyaml.org/) - Template parsing

---

<p align="center">
  <b>Built with 🌿 for the security community</b><br>
  <code>In umbris vigemus 👻</code>
</p>
