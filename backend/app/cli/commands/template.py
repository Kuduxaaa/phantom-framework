"""
Template command — discovery, filtering, validation, and inspection.

Provides reusable template utilities (discover, filter, parse metadata)
used by both the 'template' and 'scan' commands, plus the CLI handlers
for 'ph template list|validate|info'.
"""

import asyncio
import yaml
from pathlib import Path

from app.cli.display import Display, Color
from app.core.scanners.signature_scanner import SignatureScanner


TEMPLATES_DIR = Path(__file__).resolve().parents[3] / "templates"

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def discover_templates(filter_path: str | None = None) -> list[Path]:
    """
    Find YAML templates, optionally filtered by sub-path or glob.

    Args:
        filter_path: Optional path relative to templates directory.

    Returns:
        Sorted list of matching template file paths.
    """
    if filter_path:
        target = TEMPLATES_DIR / filter_path
        if target.is_file() and target.suffix in (".yaml", ".yml"):
            return [target]
        if target.is_dir():
            return sorted(target.rglob("*.yaml"))
        matches = sorted(TEMPLATES_DIR.glob(f"{filter_path}*.yaml"))
        if not matches:
            matches = sorted(TEMPLATES_DIR.glob(f"**/{filter_path}*.yaml"))
        return matches
    return sorted(TEMPLATES_DIR.rglob("*.yaml"))


def filter_templates(
    templates: list[Path],
    min_severity: str | None = None,
    tags: list[str] | None = None,
) -> list[Path]:
    """
    Filter templates by minimum severity and/or required tags.

    Args:
        templates: List of template file paths to filter.
        min_severity: Minimum severity threshold.
        tags: Required tags (at least one must match).

    Returns:
        Filtered list of template paths.
    """
    if not min_severity and not tags:
        return templates

    min_val = SEVERITY_ORDER.get(min_severity, 0) if min_severity else 0
    result = []

    for path in templates:
        meta = parse_template_meta(path)
        if SEVERITY_ORDER.get(meta["severity"], 0) < min_val:
            continue
        if tags:
            tmpl_tags = [t.lower() for t in meta["tags"]]
            if not any(t.lower() in tmpl_tags for t in tags):
                continue
        result.append(path)

    return result


def parse_template_name(path: Path) -> str:
    """
    Quick name extraction without full YAML parse.

    Args:
        path: Path to the template file.

    Returns:
        The template name string, or stem as fallback.
    """
    try:
        for line in path.open():
            stripped = line.strip()
            if stripped.startswith("name:"):
                return stripped[5:].strip().strip('"').strip("'")
    except Exception:
        pass
    return path.stem


def parse_template_meta(path: Path) -> dict:
    """
    Read full template metadata via yaml.safe_load.

    Supports both flat templates (severity/name at top level) and
    Nuclei-style templates with an 'info' block.

    Args:
        path: Path to the template file.

    Returns:
        Dictionary with id, name, severity, description, author, tags.
    """
    try:
        data = yaml.safe_load(path.read_text())
        if not isinstance(data, dict):
            return _default_meta(path)

        info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
        raw_tags = info.get("tags", data.get("tags", []))

        return {
            "id": data.get("id", path.stem),
            "name": info.get("name", data.get("name", path.stem)),
            "severity": info.get("severity", data.get("severity", "info")),
            "description": info.get("description", data.get("description", "")),
            "author": info.get("author", data.get("author", "")),
            "tags": (
                raw_tags
                if isinstance(raw_tags, list)
                else [t.strip() for t in str(raw_tags).split(",") if t.strip()]
            ),
        }
    except Exception:
        return _default_meta(path)


def _default_meta(path: Path) -> dict:
    """
    Return fallback metadata when parsing fails.

    Args:
        path: Path to the template file.

    Returns:
        Dictionary with default metadata values.
    """
    return {
        "id": path.stem,
        "name": path.stem,
        "severity": "info",
        "description": "",
        "author": "",
        "tags": [],
    }


def handle_list(args, display: Display) -> int:
    """
    Handle 'ph template list'.

    Args:
        args: Parsed CLI arguments.
        display: Display instance for terminal output.

    Returns:
        Exit code: 0 on success, 1 if no templates matched.
    """
    tag_list = (
        [t.strip() for t in args.tags.split(",")]
        if getattr(args, "tags", None)
        else None
    )
    severity = getattr(args, "severity", None)

    templates = discover_templates()
    templates = filter_templates(templates, severity, tag_list)

    if not templates:
        display.error("no templates matched filters")
        return 1

    display.template_list(templates, TEMPLATES_DIR)
    return 0


def handle_validate(args, display: Display) -> int:
    """
    Handle 'ph template validate'.

    Args:
        args: Parsed CLI arguments.
        display: Display instance for terminal output.

    Returns:
        Exit code: 0 if all passed, 1 if any failed.
    """
    return asyncio.run(_validate_async(args, display))


async def _validate_async(args, display: Display) -> int:
    """
    Async validation runner for all matching templates.

    Args:
        args: Parsed CLI arguments.
        display: Display instance for terminal output.

    Returns:
        Exit code: 0 if all passed, 1 if any failed.
    """
    filter_path = getattr(args, "template", None)
    templates = discover_templates(filter_path)
    scanner = SignatureScanner()
    passed = failed = 0

    b = display.c(Color.BOLD)
    r = display.c(Color.RESET)
    display.text(f"\n{b}Validating {len(templates)} templates...{r}\n")

    for path in templates:
        rel = path.relative_to(TEMPLATES_DIR)
        try:
            yaml_content = path.read_text()
            result = await scanner.scan_with_yaml(yaml_content, "http://localhost")
            if result.get("success") is False:
                error = result.get("error", "Unknown")
                details = result.get("validation_errors", [])
                display.validation_result(rel, False, error=error, details=details)
                failed += 1
            else:
                display.validation_result(
                    rel, True, sig_id=result.get("signature_id", "")
                )
                passed += 1
        except Exception as e:
            display.validation_result(rel, False, error=str(e))
            failed += 1

    await scanner.close()
    display.validation_summary(passed, failed)
    return 0 if failed == 0 else 1


def handle_info(args, display: Display) -> int:
    """
    Handle 'ph template info <template>'.

    Args:
        args: Parsed CLI arguments.
        display: Display instance for terminal output.

    Returns:
        Exit code: 0 on success, 1 if template not found.
    """
    templates = discover_templates(args.template)
    if not templates:
        display.error(f"template not found: {args.template}")
        return 1

    for path in templates:
        meta = parse_template_meta(path)
        display.template_detail(meta)

    return 0
