"""
Phantom Framework — MCP Server

Exposes Phantom's security scanning capabilities as MCP tools
for use by Claude, Codex, and other AI agents.
"""

import json
import yaml
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.core.scanners.http_client import HTTPClient
from app.core.scanners.signature_scanner import SignatureScanner
from app.core.scanners.crawler import Crawler
from app.core.signatures.parser import SignatureParser
from app.core.signatures.validator import SignatureValidator
from app.cli.commands.template import (
    TEMPLATES_DIR,
    discover_templates,
    filter_templates,
    parse_template_meta,
)


mcp = FastMCP(
    "Phantom",
    instructions=(
        "Phantom is a security testing framework for bug bounty and pentesting. "
        "Use these tools to scan targets for vulnerabilities, crawl websites, "
        "and manage vulnerability detection templates. "
        "Always ensure you have proper authorization before scanning any target."
    ),
)


# ── Tools ────────────────────────────────────────────────────


@mcp.tool()
async def scan(
    target_url: str,
    template_filter: str | None = None,
    severity: str | None = None,
    tags: str | None = None,
    crawl: bool = True,
    crawl_depth: int = 3,
    max_pages: int = 50,
    concurrency: int = 10,
    timeout: int = 30,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
    follow_redirects: bool = False,
) -> str:
    """Run a vulnerability scan against a target URL using YAML-based detection templates.

    This performs a full security assessment: connectivity check, optional web crawling
    for endpoint discovery, and concurrent template execution with payload injection.

    Args:
        target_url: The URL to scan (e.g. https://example.com).
        template_filter: Filter templates by path or category (e.g. "injection/sql", "fuzzing").
        severity: Minimum severity threshold: info, low, medium, high, critical.
        tags: Comma-separated tag filter (e.g. "sqli,xss,rce").
        crawl: Whether to crawl for injection endpoints before scanning.
        crawl_depth: Maximum crawl depth for link traversal.
        max_pages: Maximum pages to crawl.
        concurrency: Maximum concurrent scan workers.
        timeout: HTTP request timeout in seconds.
        headers: Custom HTTP headers to include in requests.
        proxy: Proxy URL for routing traffic (e.g. http://127.0.0.1:8080).
        follow_redirects: Whether to follow HTTP redirects.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    templates = discover_templates(template_filter)
    tag_list = [t.strip() for t in tags.split(",")] if tags else None
    templates = filter_templates(templates, severity, tag_list)

    if not templates:
        return json.dumps({"error": "No templates matched the given filters."})

    client = HTTPClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        proxy=proxy,
        headers=headers,
    )

    try:
        # Connectivity check
        resp = await client.request("GET", target_url)
        if resp.get("status_code", 0) == 0:
            await client.close()
            error = resp.get("error", "timeout / no response")
            return json.dumps({"error": f"Connection failed: {error}", "target": target_url})

        # Crawl for injection endpoints
        injection_paths: list[str] = []
        crawl_stats = {}

        if crawl:
            crawler = Crawler(
                http_client=client,
                max_depth=crawl_depth,
                max_pages=max_pages,
                concurrency=concurrency,
            )
            crawl_result = await crawler.crawl(target_url)
            injection_paths = crawl_result["injection_paths"]
            crawl_stats = {
                "pages_crawled": crawl_result["pages_crawled"],
                "parameters_found": crawl_result["parameters"],
                "forms_found": crawl_result["forms_found"],
                "injection_endpoints": len(injection_paths),
            }

        # Run templates
        sig_parser = SignatureParser()
        vulnerabilities = []
        errors = []

        for path in templates:
            yaml_content = path.read_text()
            try:
                signature = sig_parser.parse_yaml(yaml_content)
            except ValueError as e:
                errors.append({"template": path.stem, "error": f"Parse error: {e}"})
                continue

            # Inject crawled endpoints into fuzzing templates
            if injection_paths:
                for req in signature.get("requests", []):
                    if req.get("payloads"):
                        req_paths = req.get("path", [])
                        uses_injection = any("?" in p and "={{" in p for p in req_paths)
                        if uses_injection:
                            existing = set(req_paths)
                            for ip in injection_paths:
                                if ip not in existing:
                                    req["path"].append(ip)

            scanner = SignatureScanner(http_client=client, concurrency=concurrency)
            try:
                result = await scanner.scan_with_signature(signature, target_url)
            except Exception as e:
                errors.append({"template": path.stem, "error": str(e)})
                await scanner.close()
                continue
            finally:
                await scanner.close()

            if result.get("matched"):
                matches = [
                    {
                        "url": m.get("url", ""),
                        "status_code": m.get("status_code"),
                        "payload": m.get("payload", ""),
                        "extracted": m.get("extracted", {}),
                    }
                    for m in result.get("results", [])
                ]
                vulnerabilities.append({
                    "template_id": signature.get("id"),
                    "name": signature.get("name"),
                    "severity": result.get("severity", "info"),
                    "matches": matches,
                })

        await client.close()

        output: dict[str, Any] = {
            "target": target_url,
            "templates_executed": len(templates),
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }

        if crawl_stats:
            output["crawl"] = crawl_stats
        if errors:
            output["errors"] = errors

        return json.dumps(output, indent=2)

    except Exception as e:
        await client.close()
        return json.dumps({"error": str(e), "target": target_url})


@mcp.tool()
async def crawl_target(
    target_url: str,
    max_depth: int = 3,
    max_pages: int = 50,
    concurrency: int = 10,
    timeout: int = 30,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
) -> str:
    """Crawl a website to discover pages, URL parameters, and HTML forms.

    Performs breadth-first traversal to map the attack surface: links, query
    parameters, and form inputs that can be used as injection points.

    Args:
        target_url: The URL to start crawling from (e.g. https://example.com).
        max_depth: Maximum link depth to follow from the start URL.
        max_pages: Maximum number of pages to fetch.
        concurrency: Maximum concurrent HTTP requests.
        timeout: HTTP request timeout in seconds.
        headers: Custom HTTP headers.
        proxy: Proxy URL for routing traffic.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    client = HTTPClient(timeout=timeout, proxy=proxy, headers=headers)

    try:
        crawler = Crawler(
            http_client=client,
            max_depth=max_depth,
            max_pages=max_pages,
            concurrency=concurrency,
        )
        result = await crawler.crawl(target_url)
        await client.close()

        return json.dumps({
            "target": target_url,
            "pages_crawled": result["pages_crawled"],
            "parameters_found": result["parameters"],
            "forms_found": result["forms_found"],
            "injection_paths": result["injection_paths"],
        }, indent=2)

    except Exception as e:
        await client.close()
        return json.dumps({"error": str(e), "target": target_url})


@mcp.tool()
async def list_templates(
    category: str | None = None,
    severity: str | None = None,
    tags: str | None = None,
) -> str:
    """List available vulnerability detection templates.

    Templates are YAML-based signatures that define how to detect specific
    vulnerabilities (SQLi, XSS, SSRF, etc.). Each has a severity level,
    tags, and request/matcher definitions.

    Args:
        category: Filter by category path (e.g. "injection/sql", "fuzzing", "exposure").
        severity: Minimum severity threshold: info, low, medium, high, critical.
        tags: Comma-separated tag filter (e.g. "sqli,xss").
    """
    templates = discover_templates(category)
    tag_list = [t.strip() for t in tags.split(",")] if tags else None
    templates = filter_templates(templates, severity, tag_list)

    items = []
    for path in templates:
        meta = parse_template_meta(path)
        rel = str(path.relative_to(TEMPLATES_DIR)).replace("\\", "/")
        items.append({
            "path": rel,
            "id": meta["id"],
            "name": meta["name"],
            "severity": meta["severity"],
            "tags": meta["tags"],
        })

    return json.dumps({
        "templates_dir": str(TEMPLATES_DIR),
        "count": len(items),
        "templates": items,
    }, indent=2)


@mcp.tool()
async def get_template(template_path: str) -> str:
    """Get full details and YAML source of a specific vulnerability template.

    Returns template metadata (id, name, severity, description, tags) along
    with the raw YAML content and parsed request/matcher structure.

    Args:
        template_path: Path relative to templates directory (e.g. "injection/sql/error-based.yaml").
    """
    templates = discover_templates(template_path)

    if not templates:
        return json.dumps({"error": f"Template not found: {template_path}"})

    results = []
    for path in templates:
        meta = parse_template_meta(path)
        yaml_content = path.read_text()

        try:
            parsed = SignatureParser.parse_yaml(yaml_content)
            is_valid, errors = SignatureValidator.validate(parsed)
        except Exception as e:
            is_valid = False
            errors = [str(e)]
            parsed = {}

        results.append({
            "path": str(path.relative_to(TEMPLATES_DIR)).replace("\\", "/"),
            "metadata": meta,
            "valid": is_valid,
            "validation_errors": errors if not is_valid else [],
            "yaml_source": yaml_content,
            "requests_count": len(parsed.get("requests", [])),
            "matchers_count": sum(
                len(r.get("matchers", []))
                for r in parsed.get("requests", [])
            ) + len(parsed.get("matchers", [])),
        })

    return json.dumps({"templates": results}, indent=2)


@mcp.tool()
async def validate_templates(template_filter: str | None = None) -> str:
    """Validate the syntax and structure of vulnerability templates.

    Checks YAML parsing, required fields, matcher/extractor configuration,
    and attack type definitions. Reports which templates pass or fail validation.

    Args:
        template_filter: Optional path filter to validate specific templates.
    """
    templates = discover_templates(template_filter)

    if not templates:
        return json.dumps({"error": "No templates found matching filter."})

    passed = []
    failed = []

    for path in templates:
        rel = str(path.relative_to(TEMPLATES_DIR)).replace("\\", "/")
        yaml_content = path.read_text()

        try:
            parsed = SignatureParser.parse_yaml(yaml_content)
            is_valid, errors = SignatureValidator.validate(parsed)

            if is_valid:
                passed.append({"path": rel, "id": parsed.get("id", "")})
            else:
                failed.append({"path": rel, "errors": errors})
        except Exception as e:
            failed.append({"path": rel, "errors": [str(e)]})

    return json.dumps({
        "total": len(templates),
        "passed": len(passed),
        "failed": len(failed),
        "passed_templates": passed,
        "failed_templates": failed,
    }, indent=2)


@mcp.tool()
async def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int = 30,
    proxy: str | None = None,
    follow_redirects: bool = False,
) -> str:
    """Send an HTTP request and return the response details.

    Useful for manual testing, probing endpoints, or verifying
    vulnerability findings with custom requests.

    Args:
        url: Target URL.
        method: HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS).
        headers: Custom request headers.
        body: Request body content.
        timeout: Request timeout in seconds.
        proxy: Proxy URL for routing traffic.
        follow_redirects: Whether to follow HTTP redirects.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    client = HTTPClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        proxy=proxy,
    )

    try:
        response = await client.request(
            method=method.upper(),
            url=url,
            headers=headers,
            body=body,
        )
        await client.close()

        # Truncate large bodies
        resp_body = response.get("body", "")
        truncated = False
        if len(resp_body) > 10000:
            resp_body = resp_body[:10000]
            truncated = True

        return json.dumps({
            "url": response.get("url", url),
            "status_code": response.get("status_code", 0),
            "headers": response.get("headers", {}),
            "body": resp_body,
            "body_truncated": truncated,
            "elapsed_seconds": response.get("elapsed", 0),
            "error": response.get("error"),
        }, indent=2)

    except Exception as e:
        await client.close()
        return json.dumps({"error": str(e), "url": url})
