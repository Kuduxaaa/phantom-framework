#!/usr/bin/env python3
"""
Phantom Framework - Template Scanner

Usage:
    python scan.py <target_url>                                   # Run all templates
    python scan.py <target_url> -t injection/sql                  # Run a category
    python scan.py <target_url> -t injection/xss/reflected.yaml   # Run one template
    python scan.py <target_url> --tags sqli,xss --severity high   # Filter templates
    python scan.py <target_url> -d 5 --max-pages 100             # Deeper crawl
    python scan.py <target_url> --no-crawl                        # Skip crawling
    python scan.py <target_url> -o results.json --silent          # JSON output, quiet
    python scan.py -l targets.txt --tags sqli                     # Multi-target scan
    python scan.py --list                                         # List all templates
    python scan.py --validate                                     # Validate all templates
"""

import sys
import json
import asyncio
import argparse
import time
import yaml

from datetime import datetime, timezone
from pathlib import Path
from app.core.scanners.signature_scanner import SignatureScanner
from app.core.scanners.http_client import HTTPClient
from app.core.scanners.crawler import Crawler
from app.core.signatures.parser import SignatureParser


__version__ = "0.1"

TEMPLATES_DIR = Path(__file__).parent / "templates"

MAX_DISPLAY_MATCHES = 4

SEVERITY_COLORS = {
    "critical": "\033[1;91m",  # Bold Red
    "high":     "\033[91m",    # Red
    "medium":   "\033[93m",    # Yellow
    "low":      "\033[94m",    # Blue
    "info":     "\033[90m",    # Gray
}
RESET  = "\033[0m"
GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
BOLD_RED = "\033[1;91m"
BOLD_MAGENTA = "\033[1;95m"

ORANGE = "\033[38;5;208m"
TORII = f"{BOLD}{ORANGE}\u26E9{RESET}"

LOG_COLORS = {
    "INFO":     GREEN,
    "WARNING":  YELLOW,
    "ERROR":    RED,
    "CRITICAL": BOLD_RED,
    "VULN":     BOLD_MAGENTA,
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_silent = False


def log(level: str, message: str):
    """Print a timestamped log line."""
    if _silent and level == "INFO":
        return
    ts = datetime.now().strftime("%H:%M:%S")
    color = LOG_COLORS.get(level, "")
    prefix = f"[{ts}] [{color}{level}{RESET}]"
    sys.stdout.write(f"{prefix} {message}\n")
    sys.stdout.flush()


def log_detail(message: str):
    """Print an indented detail line under a log entry."""
    sys.stdout.write(f"                   {message}\n")
    sys.stdout.flush()


def parse_template_name(path: Path) -> str:
    """Extract the name field from a YAML template without a full YAML parser."""
    try:
        for line in path.open():
            stripped = line.strip()
            if stripped.startswith("name:"):
                return stripped[5:].strip().strip('"').strip("'")
    except Exception:
        pass
    return path.stem


def parse_template_meta(path: Path) -> dict:
    """Read template metadata (name, severity, tags) via yaml.safe_load."""
    try:
        data = yaml.safe_load(path.read_text())
        if not isinstance(data, dict):
            return {}
        info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
        return {
            "name": info.get("name", path.stem),
            "severity": info.get("severity", "info"),
            "tags": info.get("tags", []) if isinstance(info.get("tags"), list) else
                    [t.strip() for t in str(info.get("tags", "")).split(",") if t.strip()],
        }
    except Exception:
        return {"name": path.stem, "severity": "info", "tags": []}


def filter_templates(
    templates: list[Path],
    min_severity: str | None = None,
    tags: list[str] | None = None,
) -> list[Path]:
    """Filter templates by minimum severity level and/or required tags."""
    if not min_severity and not tags:
        return templates

    min_sev_val = SEVERITY_ORDER.get(min_severity, 0) if min_severity else 0
    result = []

    for path in templates:
        meta = parse_template_meta(path)
        template_sev = SEVERITY_ORDER.get(meta["severity"], 0)

        if template_sev < min_sev_val:
            continue

        if tags:
            template_tags = [t.lower() for t in meta["tags"]]
            if not any(t.lower() in template_tags for t in tags):
                continue

        result.append(path)

    return result


def _uses_param_injection(paths: list[str]) -> bool:
    """Check if any path contains query parameter injection markers."""
    return any('?' in p and '={{' in p for p in paths)


def parse_headers(raw_headers: list[str] | None) -> dict:
    """Parse CLI header strings ('Name: Value') into a dict."""
    headers = {}
    if not raw_headers:
        return headers
    for h in raw_headers:
        if ':' in h:
            key, value = h.split(':', 1)
            headers[key.strip()] = value.strip()
    return headers


def discover_templates(filter_path: str | None = None) -> list[Path]:
    """Find all YAML template files, optionally filtered by path."""
    if filter_path:
        target = TEMPLATES_DIR / filter_path
        if target.is_file() and target.suffix in (".yaml", ".yml"):
            return [target]
        elif target.is_dir():
            files = sorted(target.rglob("*.yaml"))
            return files
        else:
            # Try as glob pattern
            matches = sorted(TEMPLATES_DIR.glob(f"{filter_path}*.yaml"))
            if not matches:
                matches = sorted(TEMPLATES_DIR.glob(f"**/{filter_path}*.yaml"))
            return matches
    return sorted(TEMPLATES_DIR.rglob("*.yaml"))


def list_templates():
    """Print all available templates."""
    templates = discover_templates()
    if not templates:
        print(f"{RED}No templates found in {TEMPLATES_DIR}{RESET}")
        return

    print(f"\n{BOLD}Available Templates ({len(templates)}){RESET}\n")

    current_category = None
    for path in templates:
        rel = path.relative_to(TEMPLATES_DIR)
        category = str(rel.parent) if str(rel.parent) != "." else "root"

        if category != current_category:
            current_category = category
            print(f"  {CYAN}{category}/{RESET}")

        print(f"    {rel.name}")

    print()


async def validate_templates():
    """Parse and validate all templates without scanning."""
    templates = discover_templates()
    scanner = SignatureScanner()
    passed = 0
    failed = 0

    print(f"\n{BOLD}Validating {len(templates)} templates...{RESET}\n")

    for path in templates:
        rel = path.relative_to(TEMPLATES_DIR)
        try:
            yaml_content = path.read_text()
            result = await scanner.scan_with_yaml(yaml_content, "http://localhost")
            if result.get("success") is False:
                error = result.get("error", "Unknown")
                details = result.get("validation_errors", [])
                print(f"  {RED}FAIL{RESET}  {rel}")
                print(f"        {error}: {details}")
                failed += 1
            else:
                print(f"  {GREEN}OK{RESET}    {rel} {DIM}({result.get('signature_id')}){RESET}")
                passed += 1
        except Exception as e:
            print(f"  {RED}ERR{RESET}   {rel}")
            print(f"        {e}")
            failed += 1

    await scanner.close()
    print(f"\n{BOLD}Results:{RESET} {GREEN}{passed} passed{RESET}, {RED}{failed} failed{RESET}\n")
    return failed == 0


def _format_extract(extracted: dict) -> str:
    """Format extraction data into a compact inline string."""
    if not extracted:
        return ""
    parts = []
    for key, vals in extracted.items():
        if vals:
            val = str(vals[0]) if isinstance(vals, list) else str(vals)
            if len(val) > 60:
                val = val[:57] + "..."
            parts.append(f"{key}: {val}")
    return f" {DIM}({', '.join(parts)}){RESET}" if parts else ""


def print_summary(
    elapsed: float,
    total_templates: int,
    matched_count: int,
    severity_counts: dict,
    error_count: int,
    vulnerabilities: list,
    target_url: str,
):
    """Print a formatted scan summary."""
    bar = "\u2500" * 52

    print(f"\n  {DIM}{bar}{RESET}")
    print(f"  {TORII}  {BOLD}Scan Complete{RESET}")
    print(f"  {DIM}{bar}{RESET}\n")

    print(f"    {DIM}Target{RESET}       {CYAN}{target_url}{RESET}")
    print(f"    {DIM}Duration{RESET}     {BOLD}{elapsed:.1f}s{RESET}")
    print(f"    {DIM}Templates{RESET}    {total_templates} scanned")
    print()

    # Severity breakdown
    total_findings = matched_count
    if total_findings > 0:
        print(f"    {BOLD}Findings     {total_findings}{RESET}")
    else:
        print(f"    {DIM}Findings     0{RESET}")

    for sev in ("critical", "high", "medium", "low", "info"):
        count = severity_counts.get(sev, 0)
        color = SEVERITY_COLORS[sev]
        if count > 0:
            dot = f"{color}\u25cf{RESET}"
            print(f"      {dot}  {color}{sev.upper():10s}{RESET} {BOLD}{count}{RESET}")
        else:
            print(f"      {DIM}\u25cb  {sev.upper():10s} {count}{RESET}")

    print()

    # Error count
    if error_count > 0:
        print(f"    {RED}Errors       {error_count}{RESET}")
    else:
        print(f"    {DIM}Errors       0{RESET}")

    # List unique affected endpoints
    if vulnerabilities:
        affected = set()
        for v in vulnerabilities:
            for m in v.get("matches", []):
                url = m.get("url", "")
                if "?" in url:
                    base, qs = url.split("?", 1)
                    param = qs.split("=")[0] if "=" in qs else qs
                    affected.add(f"{base}?{param}=...")
                else:
                    affected.add(url)
        if affected:
            print(f"\n    {BOLD}Affected Endpoints{RESET}")
            for ep in sorted(affected):
                print(f"      {DIM}\u25b8{RESET} {ep}")

    print(f"\n  {DIM}{bar}{RESET}\n")


async def scan_target(
    target_url: str,
    filter_path: str | None = None,
    concurrency: int = 10,
    crawl_depth: int = 3,
    max_pages: int = 50,
    no_crawl: bool = False,
    timeout: int = 30,
    proxy: str | None = None,
    headers: dict | None = None,
    follow_redirects: bool = False,
    min_severity: str | None = None,
    tags: list[str] | None = None,
) -> dict:
    """Run templates against a target URL with optional crawling.

    Returns a dict with 'vulnerabilities', 'statistics', and 'errors' for
    JSON output aggregation.
    """
    templates = discover_templates(filter_path)
    templates = filter_templates(templates, min_severity, tags)

    if not templates:
        print(f"{RED}No templates found{RESET}")
        if filter_path:
            print(f"  Filter: {filter_path}")
            print(f"  Try: python scan.py --list")
        return {"vulnerabilities": [], "statistics": {}, "errors": 0}

    total = len(templates)
    start_time = time.time()

    # Collect unique categories
    categories = set()
    for p in templates:
        rel = p.relative_to(TEMPLATES_DIR)
        cat = str(rel.parent) if str(rel.parent) != "." else "root"
        categories.add(cat)

    # Header
    print(f"\n{TORII}  {BOLD}{ORANGE}phantom-framework{RESET} {DIM}v{__version__}{RESET}\n")
    log("INFO", f"target: {CYAN}{target_url}{RESET}")
    log("INFO", f"loaded {BOLD}{total}{RESET} templates from {BOLD}{len(categories)}{RESET} categories")
    log("INFO", f"concurrency: {concurrency}")

    # Connection test
    shared_client = HTTPClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        proxy=proxy,
        headers=headers,
    )
    log("INFO", "testing connection")

    target_reachable = False
    try:
        t = time.time()
        resp = await shared_client.request("GET", target_url)
        ms = (time.time() - t) * 1000
        if resp.get("status_code", 0) == 0:
            error_msg = resp.get("error") or "timeout / no response"
            log("ERROR", f"cannot reach target: {error_msg}")
            if target_url.startswith("https://"):
                http_alt = "http://" + target_url[8:]
                log("WARNING", f"target may not support HTTPS \u2014 try {CYAN}{http_alt}{RESET}")
            await shared_client.close()
            return {"vulnerabilities": [], "statistics": {}, "errors": 1}
        else:
            target_reachable = True
            log("INFO", f"target is up {DIM}(HTTP {resp['status_code']}, {ms:.0f}ms){RESET}")
    except Exception as e:
        log("ERROR", f"cannot reach target: {e}")
        await shared_client.close()
        return {"vulnerabilities": [], "statistics": {}, "errors": 1}

    # Crawl phase
    injection_paths = []
    if not no_crawl:
        log("INFO", f"crawling {DIM}(depth: {crawl_depth}, limit: {max_pages}){RESET}")

        crawler = Crawler(
            http_client=shared_client,
            max_depth=crawl_depth,
            max_pages=max_pages,
            concurrency=concurrency,
        )

        crawl_count = [0]

        def on_page(path, link_count):
            crawl_count[0] += 1

        crawl_result = await crawler.crawl(target_url, on_page=on_page)
        injection_paths = crawl_result['injection_paths']

        log("INFO",
            f"crawled {BOLD}{crawl_result['pages_crawled']}{RESET} pages, "
            f"{BOLD}{crawl_result['parameters']}{RESET} params, "
            f"{BOLD}{crawl_result['forms_found']}{RESET} forms"
        )

        if injection_paths:
            log("INFO", f"discovered {BOLD}{len(injection_paths)}{RESET} injection points")
            for ip in injection_paths:
                parts = ip.split('?', 1)
                param = parts[1].split('=')[0] if len(parts) > 1 else ''
                log_detail(f"{DIM}\u25b8{RESET} {parts[0]} {DIM}({param}){RESET}")
        else:
            log("WARNING", "no injectable parameters discovered")
    else:
        log("INFO", "crawling disabled")

    # Scanning phase
    print()
    log("INFO",
        f"scanning with {BOLD}{total}{RESET} templates"
        + (f" against {BOLD}{len(injection_paths)}{RESET} endpoints" if injection_paths else "")
    )
    print()

    sem = asyncio.Semaphore(concurrency)
    scan_progress = 0
    matched_count = 0
    error_count = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    sig_parser = SignatureParser()
    vulnerabilities = []

    async def scan_one(path):
        nonlocal scan_progress, matched_count, error_count
        rel = path.relative_to(TEMPLATES_DIR)
        template_name = parse_template_name(path)

        async with sem:
            scan_progress += 1
            progress_tag = f"{DIM}[{scan_progress}/{total}]{RESET}"
            log("INFO", f"{progress_tag} {template_name}")

            yaml_content = path.read_text()

            try:
                signature = sig_parser.parse_yaml(yaml_content)
            except ValueError as e:
                log("ERROR", f"{template_name}: parse error: {e}")
                error_count += 1
                return

            # Inject discovered paths into parameter-injection templates
            if injection_paths:
                for req in signature.get('requests', []):
                    if req.get('payloads') and _uses_param_injection(req.get('path', [])):
                        existing = set(req.get('path', []))
                        for ip in injection_paths:
                            if ip not in existing:
                                req['path'].append(ip)

            scanner = SignatureScanner(http_client=shared_client)
            try:
                result = await scanner.scan_with_signature(signature, target_url)
            except Exception as e:
                result = {"success": False, "error": str(e)}
            finally:
                await scanner.close()

            if result.get("success") is False:
                log("ERROR", f"{template_name}: {result.get('error')}")
                error_count += 1
                return

            if result.get("matched"):
                severity = result.get("severity", "info")
                sev_color = SEVERITY_COLORS.get(severity, "")

                matches_data = []
                for match in result.get("results", []):
                    matches_data.append({
                        "url": match.get("url", ""),
                        "status_code": match.get("status_code", "?"),
                        "payload": match.get("payload", ""),
                        "extracted": match.get("extracted", {}),
                    })

                # Display finding
                log("VULN",
                    f"[{sev_color}{severity.upper()}{RESET}] "
                    f"{BOLD}{template_name}{RESET} "
                    f"{DIM}({len(matches_data)} matches){RESET}"
                )

                for i, m in enumerate(matches_data):
                    if i >= MAX_DISPLAY_MATCHES:
                        remaining = len(matches_data) - MAX_DISPLAY_MATCHES
                        log_detail(f"{DIM}... {remaining} more matches{RESET}")
                        break
                    url = m["url"]
                    status = m["status_code"]
                    extract_str = _format_extract(m["extracted"])
                    log_detail(f"{url} {DIM}[{status}]{RESET}{extract_str}")

                print()

                vulnerabilities.append({
                    "template_id": signature.get("id", str(rel)),
                    "name": template_name,
                    "severity": severity,
                    "matches": matches_data,
                })

                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                matched_count += 1
            else:
                # Detect if all responses were timeouts (status 0)
                all_results = result.get("results", [])
                if all_results and all(
                    r.get("status_code", 0) == 0 for r in all_results
                ):
                    log("WARNING", f"all requests timed out for '{template_name}'")
                    error_count += 1

    await asyncio.gather(*[scan_one(p) for p in templates])
    await shared_client.close()

    elapsed = time.time() - start_time

    # Summary
    print_summary(
        elapsed=elapsed,
        total_templates=total,
        matched_count=matched_count,
        severity_counts=severity_counts,
        error_count=error_count,
        vulnerabilities=vulnerabilities,
        target_url=target_url,
    )

    return {
        "vulnerabilities": vulnerabilities,
        "statistics": {
            "total": total,
            "by_severity": dict(severity_counts),
            "duration": round(elapsed, 2),
            "errors": error_count,
        },
        "errors": error_count,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Phantom Framework - Template Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scan.py https://testphp.vulnweb.com
  python scan.py https://target.com -t injection/sql
  python scan.py https://target.com --tags sqli,xss --severity high
  python scan.py https://target.com -H "X-Custom: value" --proxy http://127.0.0.1:8080
  python scan.py -l targets.txt --tags sqli -o results.json --silent
  python scan.py --list
  python scan.py --validate
        """,
    )

    parser.add_argument(
        '--version', action='version',
        version=f'%(prog)s {__version__}',
    )

    # -- target --
    target_group = parser.add_argument_group("target")
    target_group.add_argument("target", nargs="?", help="Target URL to scan")
    target_group.add_argument("-l", "--url-list", metavar="FILE",
                              help="File with target URLs (one per line)")

    # -- templates --
    tmpl_group = parser.add_argument_group("templates")
    tmpl_group.add_argument("-t", "--template",
                            help="Template file or category to run")
    tmpl_group.add_argument("--tags", metavar="TAGS",
                            help="Filter by tags (comma-separated, e.g. sqli,xss)")
    tmpl_group.add_argument("--severity", metavar="LEVEL",
                            choices=["info", "low", "medium", "high", "critical"],
                            help="Minimum severity level: info|low|medium|high|critical")
    tmpl_group.add_argument("--list", action="store_true",
                            help="List all available templates")
    tmpl_group.add_argument("--validate", action="store_true",
                            help="Validate templates (no scan)")

    # -- crawler --
    crawl_group = parser.add_argument_group("crawler")
    crawl_group.add_argument("-d", "--depth", type=int, default=3,
                             help="Crawler depth (default: 3)")
    crawl_group.add_argument("--max-pages", type=int, default=50,
                             help="Max pages to crawl (default: 50)")
    crawl_group.add_argument("--no-crawl", action="store_true",
                             help="Skip crawling, use template paths only")

    # -- http --
    http_group = parser.add_argument_group("http")
    http_group.add_argument("-c", "--concurrency", type=int, default=10,
                            help="Number of concurrent templates (default: 10)")
    http_group.add_argument("--timeout", type=int, default=30,
                            help="HTTP request timeout in seconds (default: 30)")
    http_group.add_argument("-H", "--header", action="append", metavar="HEADER",
                            help="Custom header 'Name: Value' (repeatable)")
    http_group.add_argument("--proxy", metavar="URL",
                            help="HTTP/SOCKS proxy URL")
    http_group.add_argument("--follow-redirects", action="store_true",
                            help="Follow HTTP redirects")

    # -- output --
    out_group = parser.add_argument_group("output")
    out_group.add_argument("-o", "--output", metavar="FILE",
                           help="Save JSON results to file")
    out_group.add_argument("--silent", action="store_true",
                           help="Only show vulnerabilities (suppress INFO logs)")

    args = parser.parse_args()

    # -- silent mode --
    global _silent
    if args.silent:
        _silent = True

    # -- non-scan actions --
    if args.list:
        list_templates()
        return

    if args.validate:
        ok = asyncio.run(validate_templates())
        sys.exit(0 if ok else 1)

    # -- build target list --
    targets = []
    if args.target:
        targets.append(args.target)
    if args.url_list:
        try:
            text = Path(args.url_list).read_text()
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        except FileNotFoundError:
            print(f"{RED}URL list not found: {args.url_list}{RESET}")
            sys.exit(1)

    if not targets:
        parser.print_help()
        sys.exit(1)

    # Normalize URLs
    targets = [
        t if t.startswith(("http://", "https://")) else f"https://{t}"
        for t in targets
    ]

    # Parse CLI headers
    cli_headers = parse_headers(args.header)

    # Parse tags
    tag_list = [t.strip() for t in args.tags.split(',')] if args.tags else None

    # -- run scans --
    all_results = []

    for target in targets:
        result = asyncio.run(scan_target(
            target,
            filter_path=args.template,
            concurrency=args.concurrency,
            crawl_depth=args.depth,
            max_pages=args.max_pages,
            no_crawl=args.no_crawl,
            timeout=args.timeout,
            proxy=args.proxy,
            headers=cli_headers or None,
            follow_redirects=args.follow_redirects,
            min_severity=args.severity,
            tags=tag_list,
        ))
        all_results.append({"target": target, **result})

    # -- JSON output --
    if args.output:
        # Aggregate statistics
        total_vulns = sum(len(r["vulnerabilities"]) for r in all_results)
        total_errors = sum(r["errors"] for r in all_results)
        total_duration = sum(r["statistics"].get("duration", 0) for r in all_results)

        agg_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        all_vulns = []
        for r in all_results:
            all_vulns.extend(r["vulnerabilities"])
            for sev, count in r["statistics"].get("by_severity", {}).items():
                agg_severity[sev] = agg_severity.get(sev, 0) + count

        output = {
            "info": {
                "version": __version__,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "targets": [r["target"] for r in all_results],
            },
            "vulnerabilities": all_vulns,
            "statistics": {
                "total": total_vulns,
                "by_severity": agg_severity,
                "duration": round(total_duration, 2),
                "errors": total_errors,
            },
        }

        Path(args.output).write_text(json.dumps(output, indent=2))
        log("INFO", f"results saved to {CYAN}{args.output}{RESET}")


if __name__ == "__main__":
    main()
