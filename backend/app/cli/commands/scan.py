"""
Scan command — target vulnerability scanning.

Orchestrates the full scan lifecycle: target resolution, connection
testing, crawling, concurrent template execution, and result output.
"""

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from app.cli import __version__
from app.cli.display import Display, Color
from app.cli.commands.template import (
    TEMPLATES_DIR,
    discover_templates,
    filter_templates,
    parse_template_name,
)
from app.core.scanners.signature_scanner import SignatureScanner
from app.core.scanners.http_client import HTTPClient
from app.core.scanners.crawler import Crawler
from app.core.signatures.parser import SignatureParser


def handle(args, display: Display) -> int:
    """
    Entry point for 'ph scan'.

    Resolves targets, dispatches scanning for each, and writes
    optional JSON output.

    Args:
        args: Parsed CLI arguments.
        display: Display instance for terminal output.

    Returns:
        Exit code: 0 clean, 1 vulnerabilities found, 2 errors.
    """

    targets = _resolve_targets(args, display)
    if not targets:
        display.error("no targets specified (use <url> or -l <file>)")
        return 2

    headers = _parse_headers(args.header)
    tags = (
        [t.strip() for t in args.tags.split(",")]
        if args.tags
        else None
    )

    all_results = []
    for target in targets:
        result = asyncio.run(
            _scan_target(
                target,
                display=display,
                filter_path=args.template,
                concurrency=args.concurrency,
                crawl_depth=args.depth,
                max_pages=args.max_pages,
                no_crawl=args.no_crawl,
                timeout=args.timeout,
                proxy=args.proxy,
                headers=headers or None,
                follow_redirects=args.follow_redirects,
                min_severity=args.severity,
                tags=tags,
            )
        )
        all_results.append({"target": target, **result})

    if args.output:
        _write_json(all_results, args.output, display)

    total_vulns = sum(len(r["vulnerabilities"]) for r in all_results)
    total_errors = sum(r["errors"] for r in all_results)

    if total_errors and not total_vulns:
        return 2
    return 1 if total_vulns else 0


def _resolve_targets(args, display: Display) -> list[str]:
    """
    Build normalized target list from CLI arguments.

    Reads targets from positional argument and/or a file, prepending
    https:// to bare hostnames.

    Args:
        args: Parsed CLI arguments.
        display: Display instance for error output.

    Returns:
        List of fully qualified target URLs.
    """

    targets = []

    if args.target:
        targets.append(args.target)

    if args.url_list:
        path = Path(args.url_list)
        if not path.exists():
            display.error(f"file not found: {args.url_list}")
            return []
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)

    return [
        t if t.startswith(("http://", "https://")) else f"https://{t}"
        for t in targets
    ]


def _parse_headers(raw: list[str] | None) -> dict:
    """
    Parse 'Name: Value' header strings into a dict.

    Args:
        raw: List of raw header strings from CLI.

    Returns:
        Dictionary mapping header names to values.
    """

    if not raw:
        return {}
    
    headers = {}
    
    for h in raw:
        if ":" in h:
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()
    
    return headers


def _uses_param_injection(paths: list[str]) -> bool:
    """
    Check if any request path uses query parameter injection markers.

    Args:
        paths: List of URL path templates.

    Returns:
        True if any path contains injection placeholders.
    """

    return any("?" in p and "={{" in p for p in paths)


async def _scan_target(
    target_url: str,
    display: Display,
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
    """
    Execute a full scan against a single target.

    Loads templates, tests connectivity, crawls for injection points,
    then runs all templates concurrently with a semaphore-limited
    worker pool.

    Args:
        target_url: The URL to scan.
        display: Display instance for terminal output.
        filter_path: Optional template path or category filter.
        concurrency: Maximum concurrent scan workers.
        crawl_depth: Maximum crawl depth.
        max_pages: Maximum pages to crawl.
        no_crawl: Skip crawling entirely.
        timeout: HTTP request timeout in seconds.
        proxy: Optional proxy URL.
        headers: Optional custom HTTP headers.
        follow_redirects: Whether to follow HTTP redirects.
        min_severity: Minimum severity level filter.
        tags: Optional tag filter list.

    Returns:
        Dictionary with vulnerabilities, statistics, and error count.
    """

    templates = discover_templates(filter_path)
    templates = filter_templates(templates, min_severity, tags)

    if not templates:
        display.error("no templates matched filters")
        return {"vulnerabilities": [], "statistics": {}, "errors": 0}

    total = len(templates)
    start = time.time()

    categories = {
        str(p.relative_to(TEMPLATES_DIR).parent)
        if str(p.relative_to(TEMPLATES_DIR).parent) != "."
        else "root"
        for p in templates
    }

    b = display.c(Color.BOLD)
    d = display.c(Color.DIM)
    cy = display.c(Color.CYAN)
    r = display.c(Color.RESET)

    display.banner(__version__)

    display.phase("target")
    display.text(f"    {cy}{target_url}{r}")

    display.phase("recon")

    client = HTTPClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        proxy=proxy,
        headers=headers,
    )

    try:
        t0 = time.time()
        resp = await client.request("GET", target_url)
        ms = (time.time() - t0) * 1000

        if resp.get("status_code", 0) == 0:
            err = resp.get("error") or "timeout / no response"
            display.check("connection", err, ok=False)
            if target_url.startswith("https://"):
                alt = "http://" + target_url[8:]
                display.warn(
                    f"target may not support HTTPS \u2014 try {cy}{alt}{r}"
                )
            await client.close()
            return {"vulnerabilities": [], "statistics": {}, "errors": 1}

        display.check(
            "connection",
            f"HTTP {resp['status_code']} {d}({ms:.0f}ms){r}",
        )
    except Exception as e:
        display.check("connection", str(e), ok=False)
        await client.close()
        return {"vulnerabilities": [], "statistics": {}, "errors": 1}

    injection_paths = []

    if not no_crawl:
        crawler = Crawler(
            http_client=client,
            max_depth=crawl_depth,
            max_pages=max_pages,
            concurrency=concurrency,
        )

        crawl_result = await crawler.crawl(target_url)
        injection_paths = crawl_result["injection_paths"]

        display.check(
            "crawl",
            f"{crawl_result['pages_crawled']} pages "
            f"{d}\u00b7{r} {crawl_result['parameters']} params "
            f"{d}\u00b7{r} {crawl_result['forms_found']} forms",
        )

        if injection_paths:
            display.status(
                "injection",
                f"{b}{len(injection_paths)}{r} endpoints discovered",
            )
            pad = " " * 21
            for ip in injection_paths:
                parts = ip.split("?", 1)
                param = parts[1].split("=")[0] if len(parts) > 1 else ""
                display.text(
                    f"{pad}{d}{display.BULLET}{r} {parts[0]} {d}({param}){r}"
                )
        else:
            display.status("injection", f"{d}no parameters discovered{r}")
    else:
        display.status("crawl", f"{d}disabled{r}")

    display.phase("scan")
    display.status(
        "templates",
        f"{b}{total}{r} loaded {d}\u00b7{r} {len(categories)} categories",
    )

    display.blank()
    sem = asyncio.Semaphore(concurrency)

    progress = [0]
    matched = [0]
    errors = [0]
    severity_counts = {
        "critical": 0, 
        "high": 0,
        "medium": 0, 
        "low": 0,
        "info": 0,
    }

    sig_parser = SignatureParser()
    vulns = []

    display.progress_start()

    async def _scan_one(path):
        """
        Run a single template against the target.
        """
        
        template_name = parse_template_name(path)
        rel = path.relative_to(TEMPLATES_DIR)

        async with sem:
            progress[0] += 1
            display.progress_update(progress[0], total, template_name)

            yaml_content = path.read_text()

            try:
                signature = sig_parser.parse_yaml(yaml_content)
            except ValueError as e:
                display.error(f"{template_name}: parse error: {e}")
                errors[0] += 1
                return

            if injection_paths:
                for req in signature.get("requests", []):
                    if req.get("payloads") and _uses_param_injection(
                        req.get("path", [])
                    ):
                        existing = set(req.get("path", []))
                        for ip in injection_paths:
                            if ip not in existing:
                                req["path"].append(ip)

            scanner = SignatureScanner(http_client=client)
            
            try:
                result = await scanner.scan_with_signature(
                    signature, target_url
                )
            
            except Exception as e:
                result = {
                    "success": False, 
                    "error": str(e)
                }
            
            finally:
                await scanner.close()

            if result.get("success") is False:
                display.error(
                    f"{template_name}: {result.get('error')}"
                )

                errors[0] += 1
                return

            if result.get("matched"):
                severity = result.get("severity", "info")
                matches_data = [
                    {
                        "url": m.get("url", ""),
                        "status_code": m.get("status_code", "?"),
                        "payload": m.get("payload", ""),
                        "extracted": m.get("extracted", {}),
                    }
                    for m in result.get("results", [])
                ]

                display.finding(template_name, severity, matches_data)

                vulns.append({
                    "template_id": signature.get("id", str(rel)),
                    "name": template_name,
                    "severity": severity,
                    "matches": matches_data,
                })

                severity_counts[severity] = (
                    severity_counts.get(severity, 0) + 1
                )

                matched[0] += 1

            else:
                all_results = result.get("results", [])
                if all_results and all(
                    ri.get("status_code", 0) == 0 for ri in all_results
                ):
                    display.warn(
                        f"all requests timed out for '{template_name}'"
                    )

                    errors[0] += 1

    await asyncio.gather(*[_scan_one(p) for p in templates])
    display.progress_end()
    await client.close()

    elapsed = time.time() - start

    display.summary(
        elapsed=elapsed,
        total_templates=total,
        matched_count=matched[0],
        severity_counts=severity_counts,
        error_count=errors[0],
        vulnerabilities=vulns,
        target_url=target_url,
    )

    return {
        "vulnerabilities": vulns,
        "statistics": {
            "total": total,
            "by_severity": dict(severity_counts),
            "duration": round(elapsed, 2),
            "errors": errors[0],
        },
        "errors": errors[0],
    }


def _write_json(results: list[dict], path: str, display: Display):
    """
    Aggregate multi-target results and write JSON output.

    Args:
        results: List of per-target result dictionaries.
        path: Output file path.
        display: Display instance for status output.
    """
    
    total_duration = sum(
        r["statistics"].get("duration", 0) for r in results
    )

    agg_severity = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    all_vulns = []

    for r in results:
        all_vulns.extend(r["vulnerabilities"])
        for sev, count in r["statistics"].get("by_severity", {}).items():
            agg_severity[sev] = agg_severity.get(sev, 0) + count

    output = {
        "info": {
            "version": __version__,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "targets": [r["target"] for r in results],
        },
        "vulnerabilities": all_vulns,
        "statistics": {
            "total": len(all_vulns),
            "by_severity": agg_severity,
            "duration": round(total_duration, 2),
            "errors": sum(r["errors"] for r in results),
        },
    }

    cy = display.c(Color.CYAN)
    r = display.c(Color.RESET)
    Path(path).write_text(json.dumps(output, indent=2))
    display.info(f"results saved to {cy}{path}{r}")
