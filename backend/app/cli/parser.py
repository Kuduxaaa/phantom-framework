"""
Argument parser for Phantom CLI.

Defines the full command structure with subcommands, argument groups,
and handler routing. Supports implicit default to 'scan' when the
first argument looks like a target URL or flag.
"""

import argparse
from app.cli import __version__


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level parser with scan/template subcommands."""
    parser = argparse.ArgumentParser(
        prog="ph",
        description="Phantom \u26E9  Template-based vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_epilog(),
    )

    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subs = parser.add_subparsers(dest="command", metavar="<command>")

    # ── scan ───────────────────────────────────────────────

    scan_p = subs.add_parser(
        "scan",
        help="scan target(s) for vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Run detection templates against one or more targets.",
    )
    _add_scan_args(scan_p)

    from app.cli.commands.scan import handle as scan_handle
    scan_p.set_defaults(handler=scan_handle)

    # ── template ───────────────────────────────────────────

    tmpl_p = subs.add_parser(
        "template",
        help="manage detection templates",
        description="List, validate, and inspect detection templates.",
    )

    tmpl_subs = tmpl_p.add_subparsers(
        dest="template_command", metavar="<subcommand>",
    )

    # template list
    tl = tmpl_subs.add_parser("list", help="list available templates")
    tl.add_argument(
        "--tags", metavar="TAGS",
        help="filter by tags (comma-separated)",
    )
    tl.add_argument(
        "--severity", metavar="LEVEL",
        choices=["info", "low", "medium", "high", "critical"],
        help="minimum severity level",
    )
    tl.add_argument("--no-color", action="store_true", help="disable colors")

    from app.cli.commands.template import handle_list
    tl.set_defaults(handler=handle_list)

    # template validate
    tv = tmpl_subs.add_parser("validate", help="validate template syntax")
    tv.add_argument(
        "-t", "--template", metavar="PATH",
        help="specific template or category to validate",
    )
    tv.add_argument("--no-color", action="store_true", help="disable colors")

    from app.cli.commands.template import handle_validate
    tv.set_defaults(handler=handle_validate)

    # template info
    ti = tmpl_subs.add_parser("info", help="show template details")
    ti.add_argument("template", help="template path (relative to templates/)")
    ti.add_argument("--no-color", action="store_true", help="disable colors")

    from app.cli.commands.template import handle_info
    ti.set_defaults(handler=handle_info)

    # bare 'ph template' shows help
    tmpl_p.set_defaults(handler=lambda a, d: tmpl_p.print_help() or 0)

    return parser


def _add_scan_args(p: argparse.ArgumentParser):
    """Register all argument groups for the scan subcommand."""

    # ── target ─────────────────────────────────────────────
    tg = p.add_argument_group("target")
    tg.add_argument("target", nargs="?", help="target URL to scan")
    tg.add_argument(
        "-l", "--url-list", metavar="FILE",
        help="file with target URLs (one per line)",
    )

    # ── templates ──────────────────────────────────────────
    tp = p.add_argument_group("templates")
    tp.add_argument(
        "-t", "--template", metavar="PATH",
        help="template file or category to run",
    )
    tp.add_argument(
        "--tags", metavar="TAGS",
        help="filter by tags (comma-separated, e.g. sqli,xss)",
    )
    tp.add_argument(
        "--severity", metavar="LEVEL",
        choices=["info", "low", "medium", "high", "critical"],
        help="minimum severity: info|low|medium|high|critical",
    )

    # ── crawler ────────────────────────────────────────────
    cg = p.add_argument_group("crawler")
    cg.add_argument(
        "-d", "--depth", type=int, default=3,
        help="crawl depth (default: 3)",
    )
    cg.add_argument(
        "--max-pages", type=int, default=50,
        help="max pages to crawl (default: 50)",
    )
    cg.add_argument(
        "--no-crawl", action="store_true",
        help="skip crawling, use template paths only",
    )

    # ── http ───────────────────────────────────────────────
    hg = p.add_argument_group("http")
    hg.add_argument(
        "-c", "--concurrency", type=int, default=10,
        help="concurrent scan workers (default: 10)",
    )
    hg.add_argument(
        "--timeout", type=int, default=30,
        help="request timeout in seconds (default: 30)",
    )
    hg.add_argument(
        "-H", "--header", action="append", metavar="HEADER",
        help="custom header 'Name: Value' (repeatable)",
    )
    hg.add_argument(
        "--proxy", metavar="URL",
        help="HTTP/SOCKS proxy URL",
    )
    hg.add_argument(
        "-L", "--follow-redirects", action="store_true",
        help="follow HTTP redirects",
    )

    # ── output ─────────────────────────────────────────────
    og = p.add_argument_group("output")
    og.add_argument(
        "-o", "--output", metavar="FILE",
        help="write JSON results to file",
    )
    og.add_argument(
        "--silent", action="store_true",
        help="suppress informational output",
    )
    og.add_argument(
        "--no-color", action="store_true",
        help="disable colored output",
    )


def _epilog() -> str:
    return """\
examples:
  ph https://target.com                              scan with all templates
  ph https://target.com -t injection/sql             scan with SQL templates
  ph https://target.com --tags sqli --severity high  filter by tag & severity
  ph https://target.com -H "Auth: Bearer tok"        custom headers
  ph https://target.com --proxy http://127.0.0.1:8080
  ph -l targets.txt -o results.json --silent         multi-target, JSON output
  ph template list --severity high                   list high-sev templates
  ph template validate                               validate all templates
  ph template info injection/sql/error-based.yaml    show template details
"""
