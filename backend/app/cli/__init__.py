"""
Phantom CLI — command-line interface for Phantom Framework.

This module is the independent CLI controller, separated from the
scanner core. It owns argument parsing, display formatting, and
command dispatch, while delegating scanning logic to app.core.
"""

import sys

__version__ = "0.2.1"


def main():
    """CLI entry point — parse args, dispatch to command handler."""
    from app.cli.parser import build_parser
    from app.cli.display import Display

    _apply_default_subcommand()

    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "handler"):
        parser.print_help()
        sys.exit(0)

    use_color = sys.stdout.isatty() and not getattr(args, "no_color", False)
    display = Display(
        color=use_color,
        silent=getattr(args, "silent", False),
    )

    try:
        exit_code = args.handler(args, display)
    except KeyboardInterrupt:
        display.progress_end()
        display.blank()
        display.warn("interrupted by user")
        exit_code = 130

    sys.exit(exit_code or 0)


def _apply_default_subcommand():
    """Implicit 'scan' when first argument isn't a known subcommand.

    Allows 'ph https://target.com' as shorthand for 'ph scan https://target.com'.
    """
    if len(sys.argv) < 2:
        return

    first = sys.argv[1]
    if first in ("-h", "--help", "-V", "--version"):
        return
    if first not in ("scan", "template"):
        sys.argv.insert(1, "scan")
