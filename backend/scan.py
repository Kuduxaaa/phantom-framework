#!/usr/bin/env python3
"""
Phantom Framework - Template Scanner

Usage:
    python scan.py <target_url>                                   # Run all templates
    python scan.py <target_url> -t injection/sql                  # Run a category
    python scan.py <target_url> -t injection/xss/reflected.yaml   # Run one template
    python scan.py --list                                         # List all templates
    python scan.py --validate                                     # Validate all templates (no scan)
"""

import sys
import asyncio
import argparse
import time

from pathlib import Path
from app.core.scanners.signature_scanner import SignatureScanner
from app.core.scanners.http_client import HTTPClient


TEMPLATES_DIR = Path(__file__).parent / "templates"

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


async def scan_target(target_url: str, filter_path: str | None = None, concurrency: int = 10):
    """Run templates against a target URL concurrently."""
    templates = discover_templates(filter_path)
    if not templates:
        print(f"{RED}No templates found{RESET}")
        if filter_path:
            print(f"  Filter: {filter_path}")
            print(f"  Try: python scan.py --list")
        return

    total = len(templates)
    start_time = time.time()

    print(f"\n{BOLD}Phantom Framework - Template Scanner{RESET}")
    print(f"  Target:      {CYAN}{target_url}{RESET}")
    print(f"  Templates:   {total}")
    print(f"  Concurrency: {concurrency}")
    print(f"  Directory:   {TEMPLATES_DIR}\n")
    print(f"{'─' * 70}")

    # Shared HTTP client for connection pooling across all scanners
    shared_client = HTTPClient()
    sem = asyncio.Semaphore(concurrency)
    completed = 0

    async def scan_one(path):
        nonlocal completed
        async with sem:
            scanner = SignatureScanner(http_client=shared_client)
            yaml_content = path.read_text()
            try:
                result = await scanner.scan_with_yaml(yaml_content, target_url)
            except Exception as e:
                result = {"success": False, "error": str(e)}
            finally:
                await scanner.close()

            completed += 1
            sys.stdout.write(f"\r  Progress: {completed}/{total} templates...")
            sys.stdout.flush()

            return result

    results = await asyncio.gather(*[scan_one(p) for p in templates])

    # Clear progress line
    sys.stdout.write(f"\r{'':60}\r")
    sys.stdout.flush()

    # Print results in order
    matched_count = 0
    error_count = 0

    for idx, (path, result) in enumerate(zip(templates, results), 1):
        rel = path.relative_to(TEMPLATES_DIR)
        prefix = f"  [{idx}/{total}]"

        if result.get("success") is False:
            sys.stdout.write(f"{prefix} {RED}ERROR{RESET}  {rel}: {result.get('error')}\n")
            error_count += 1
            continue

        if result.get("matched"):
            severity = result.get("severity", "info")
            color = SEVERITY_COLORS.get(severity, "")
            name = result.get("signature_name", "")
            sys.stdout.write(
                f"{prefix} {color}[{severity.upper()}]{RESET} {BOLD}{name}{RESET} {DIM}({rel}){RESET}\n"
            )

            for match in result.get("results", []):
                url = match.get("url", "")
                status = match.get("status_code", "?")
                payload = match.get("payload", "")
                extracted = match.get("extracted", {})

                print(f"        {DIM}URL:{RESET} {url} {DIM}[{status}]{RESET}")
                if payload:
                    display = payload[:80] + "..." if len(payload) > 80 else payload
                    print(f"        {DIM}Payload:{RESET} {display}")
                if extracted:
                    for key, vals in extracted.items():
                        print(f"        {DIM}Extract ({key}):{RESET} {vals}")

            matched_count += 1
        else:
            sys.stdout.write(f"{prefix} {GREEN}CLEAN{RESET}  {rel}\n")

    await shared_client.close()
    elapsed = time.time() - start_time

    print(f"{'─' * 70}")
    print(f"\n{BOLD}Summary{RESET}")
    print(f"  Scanned:  {total} templates in {elapsed:.1f}s")
    print(f"  Found:    {BOLD}{matched_count}{RESET} vulnerabilities")
    if error_count:
        print(f"  Errors:   {RED}{error_count}{RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Phantom Framework - Template Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scan.py https://testphp.vulnweb.com
  python scan.py https://target.com -t injection/sql
  python scan.py https://target.com -t fuzzing/xss.yaml
  python scan.py https://target.com -c 20
  python scan.py --list
  python scan.py --validate
        """,
    )

    parser.add_argument("target", nargs="?", help="Target URL to scan")
    parser.add_argument("-t", "--template", help="Template file or category to run")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Number of concurrent templates (default: 10)")
    parser.add_argument("--list", action="store_true", help="List all available templates")
    parser.add_argument("--validate", action="store_true", help="Validate templates (no scan)")

    args = parser.parse_args()

    if args.list:
        list_templates()
        return

    if args.validate:
        ok = asyncio.run(validate_templates())
        sys.exit(0 if ok else 1)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    target = args.target
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    asyncio.run(scan_target(target, args.template, args.concurrency))


if __name__ == "__main__":
    main()
