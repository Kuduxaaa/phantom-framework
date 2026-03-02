"""
Phantom CLI display engine.

Centralizes all terminal output — colors, logging, progress bar,
findings, scan summaries, and template formatting.  Supports color
toggling, silent mode, and a live progress bar with auto-suspend.
"""

import sys
import time
from datetime import datetime


class Color:
    """
    ANSI escape code constants.
    """

    RESET       = "\033[0m"
    BOLD        = "\033[1m"
    DIM         = "\033[2m"

    RED         = "\033[91m"
    GREEN       = "\033[92m"
    YELLOW      = "\033[93m"
    BLUE        = "\033[94m"
    MAGENTA     = "\033[95m"
    CYAN        = "\033[96m"
    GRAY        = "\033[90m"
    WHITE       = "\033[97m"

    BOLD_RED    = "\033[1;91m"
    BOLD_GREEN  = "\033[1;92m"
    BOLD_MAGENTA = "\033[1;95m"
    ORANGE      = "\033[38;5;208m"

    SEVERITY = {
        "critical": "\033[1;91m",
        "high":     "\033[91m",
        "medium":   "\033[93m",
        "low":      "\033[94m",
        "info":     "\033[90m",
    }

    LOG_LEVEL = {
        "INFO":     "\033[92m",
        "WARNING":  "\033[93m",
        "ERROR":    "\033[91m",
        "CRITICAL": "\033[1;91m",
        "VULN":     "\033[1;95m",
    }


class Display:
    """
    Terminal output controller.

    All CLI output flows through this class.  When a progress bar is
    active it is automatically suspended before any write and redrawn
    afterwards, so findings and log lines always appear above the bar.
    """

    TORII       = "\u26E9"
    HR          = "\u2500" * 52
    BULLET      = "\u25b8"
    DOT_FILLED  = "\u25cf"
    DOT_EMPTY   = "\u25cb"
    CHECK       = "\u2713"
    CROSS       = "\u2717"
    MAX_MATCHES = 4
    SEVERITIES  = ("critical", "high", "medium", "low", "info")
    _FINDING_INDENT = " " * 14

    def __init__(self, color: bool = True, silent: bool = False):
        self._color = color
        self._silent = silent
        self._is_tty = sys.stdout.isatty()
        self._bar_active = False
        self._bar_state = (0, 0, "")
        self._bar_start = 0.0

    @property
    def silent(self) -> bool:
        return self._silent

    @silent.setter
    def silent(self, value: bool):
        self._silent = value

    def c(self, code: str) -> str:
        """
        Return the ANSI code if color is enabled, empty string otherwise.
        """
        return code if self._color else ""

    def _write(self, text: str):
        """
        Write a single line to stdout.

        Automatically suspends an active progress bar before writing
        and redraws it afterwards.
        """
        if self._bar_active and self._is_tty:
            sys.stdout.write("\r\033[K")
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
        if self._bar_active and self._is_tty:
            self._render_bar(*self._bar_state)

    def text(self, message: str):
        """
        Print a raw line of text.
        """
        self._write(message)

    def blank(self):
        """
        Print an empty line.
        """
        self._write("")

    def log(self, level: str, message: str):
        """
        Print a timestamped log line.

        Args:
            level: Log level (INFO, WARNING, ERROR, CRITICAL, VULN).
            message: Message body.
        """
        if self._silent and level == "INFO":
            return
        ts = datetime.now().strftime("%H:%M:%S")
        lc = self.c(Color.LOG_LEVEL.get(level, ""))
        r  = self.c(Color.RESET)
        self._write(f"[{ts}] [{lc}{level}{r}] {message}")

    def detail(self, message: str):
        """
        Print an indented detail line beneath a log entry.
        """
        self._write(f"                   {message}")

    def info(self, message: str):
        """
        Shorthand for log('INFO', message).
        """
        self.log("INFO", message)

    def warn(self, message: str):
        """
        Shorthand for log('WARNING', message).
        """
        self.log("WARNING", message)

    def error(self, message: str):
        """
        Shorthand for log('ERROR', message).
        """
        self.log("ERROR", message)

    def banner(self, version: str):
        """
        Print the Phantom startup banner.

        Args:
            version: Version string to display.
        """
        b = self.c(Color.BOLD)
        o = self.c(Color.ORANGE)
        d = self.c(Color.DIM)
        r = self.c(Color.RESET)
        t = f"{b}{o}{self.TORII}{r}"
        self._write(f"\n{t}  {b}{o}phantom{r} {d}v{version}{r}")

    def phase(self, name: str):
        """
        Print a section header that visually separates scan phases.

        Args:
            name: Phase label (e.g. 'target', 'recon', 'scan').
        """
        d = self.c(Color.DIM)
        b = self.c(Color.BOLD)
        r = self.c(Color.RESET)
        right_len = max(48 - len(name), 3)
        self._write(f"\n  {d}\u2500\u2500\u2500{r} {b}{name}{r} {d}{'\u2500' * right_len}{r}")

    def check(self, label: str, value: str, ok: bool = True):
        """
        Print a status line with a check or cross indicator.

        Args:
            label: Left-aligned label (e.g. 'connection').
            value: Status description.
            ok: True for check mark, False for cross.
        """
        g  = self.c(Color.BOLD_GREEN)
        rd = self.c(Color.RED)
        d  = self.c(Color.DIM)
        r  = self.c(Color.RESET)
        icon = f"{g}{self.CHECK}{r}" if ok else f"{rd}{self.CROSS}{r}"
        self._write(f"    {d}{label:13s}{r} {icon}  {value}")

    def status(self, label: str, value: str):
        """
        Print a status line without check/cross icon, aligned with check lines.

        Args:
            label: Left-aligned label.
            value: Status description.
        """
        d = self.c(Color.DIM)
        r = self.c(Color.RESET)
        self._write(f"    {d}{label:13s}{r}    {value}")

    def progress_start(self):
        """
        Begin progress bar tracking.
        """
        self._bar_active = True
        self._bar_state = (0, 0, "")
        self._bar_start = time.time()

    def progress_update(self, current: int, total: int, label: str = ""):
        """
        Update the progress indicator.

        In TTY mode draws an in-place bar. In non-TTY mode falls back
        to per-template log lines (unless silent).

        Args:
            current: Number of items processed so far.
            total: Total number of items.
            label: Name of the current item.
        """
        self._bar_state = (current, total, label)
        if self._is_tty:
            self._render_bar(current, total, label)
        elif not self._silent:
            d = self.c(Color.DIM)
            r = self.c(Color.RESET)
            self.info(f"{d}[{current}/{total}]{r} {label}")

    def progress_end(self):
        """
        Finish progress tracking and clear the bar line.
        """
        if self._bar_active and self._is_tty:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
        self._bar_active = False

    def _render_bar(self, current: int, total: int, label: str):
        """
        Draw the progress bar on the current line without a trailing newline.

        Args:
            current: Number of items processed so far.
            total: Total number of items.
            label: Name of the current item.
        """
        if total <= 0:
            return

        elapsed = time.time() - self._bar_start

        width  = 28
        filled = int(width * current / total)
        bar_on  = "\u2588" * filled
        bar_off = "\u2591" * (width - filled)

        mins, secs = divmod(int(elapsed), 60)
        elapsed_str = f"{mins}m{secs:02d}s" if mins else f"{secs}s"

        max_len = 32
        if len(label) > max_len:
            label = label[: max_len - 2] + ".."

        o = self.c(Color.ORANGE)
        d = self.c(Color.DIM)
        r = self.c(Color.RESET)

        line = (
            f"\r    {o}{bar_on}{d}{bar_off}{r}"
            f"  {current}/{total}  {d}{elapsed_str}  {label}{r}\033[K"
        )
        sys.stdout.write(line)
        sys.stdout.flush()

    def finding(self, name: str, severity: str, matches: list[dict]):
        """
        Display a vulnerability finding with severity badge and match details.

        Args:
            name: Template name.
            severity: Severity level string.
            matches: List of match detail dicts.
        """
        sc = self.c(Color.SEVERITY.get(severity, ""))
        b  = self.c(Color.BOLD)
        d  = self.c(Color.DIM)
        r  = self.c(Color.RESET)

        n = len(matches)
        count = f"1 match" if n == 1 else f"{n} matches"

        self._write(
            f"  {sc}{self.DOT_FILLED}{r} {sc}{severity.upper():8s}{r}"
            f"  {b}{name}{r}  {d}{count}{r}"
        )

        indent = self._FINDING_INDENT
        for i, m in enumerate(matches):
            if i >= self.MAX_MATCHES:
                rest = n - self.MAX_MATCHES
                self._write(f"{indent}{d}+ {rest} more{r}")
                break
            url    = m.get("url", "")
            status = m.get("status_code", "?")
            ext    = self._format_extract(m.get("extracted", {}))
            self._write(
                f"{indent}{d}{self.BULLET}{r} {url} {d}[{status}]{r}{ext}"
            )

        self.blank()

    def summary(
        self, *,
        elapsed: float,
        total_templates: int,
        matched_count: int,
        severity_counts: dict,
        error_count: int,
        vulnerabilities: list,
        target_url: str,
    ):
        """
        Print the formatted end-of-scan summary report.

        Args:
            elapsed: Total scan duration in seconds.
            total_templates: Number of templates executed.
            matched_count: Number of templates that matched.
            severity_counts: Dict mapping severity to finding count.
            error_count: Number of scan errors.
            vulnerabilities: List of vulnerability result dicts.
            target_url: The scanned target URL.
        """
        b  = self.c(Color.BOLD)
        d  = self.c(Color.DIM)
        cy = self.c(Color.CYAN)
        rd = self.c(Color.RED)
        g  = self.c(Color.GREEN)
        o  = self.c(Color.ORANGE)
        r  = self.c(Color.RESET)

        hr = f"{d}{self.HR}{r}"
        t  = f"{b}{o}{self.TORII}{r}"

        self._write(f"\n  {hr}")
        self._write(f"  {t}  {b}Scan Complete{r}")
        self._write(f"  {hr}\n")

        self._write(f"    {d}Target{r}       {cy}{target_url}{r}")
        self._write(f"    {d}Duration{r}     {b}{elapsed:.1f}s{r}")
        self._write(f"    {d}Templates{r}    {total_templates} scanned")
        self.blank()

        if matched_count > 0:
            self._write(f"    {b}Findings     {matched_count}{r}")
        else:
            label = f"{g}clean \u2014 no vulnerabilities found{r}"
            self._write(f"    {d}Findings{r}     {label}")

        for sev in self.SEVERITIES:
            count = severity_counts.get(sev, 0)
            sc = self.c(Color.SEVERITY[sev])
            if count > 0:
                dot = f"{sc}{self.DOT_FILLED}{r}"
                self._write(
                    f"      {dot}  {sc}{sev.upper():10s}{r} {b}{count}{r}"
                )
            else:
                self._write(
                    f"      {d}{self.DOT_EMPTY}  {sev.upper():10s} {count}{r}"
                )

        self.blank()

        if error_count > 0:
            self._write(f"    {rd}Errors       {error_count}{r}")
        else:
            self._write(f"    {d}Errors       0{r}")

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
                self._write(f"\n    {b}Affected Endpoints{r}")
                for ep in sorted(affected):
                    self._write(f"      {d}{self.BULLET}{r} {ep}")

        self._write(f"\n  {hr}\n")

    def template_list(self, templates: list, templates_dir):
        """
        Print a categorized template listing.

        Args:
            templates: List of template Path objects.
            templates_dir: Root templates directory for relative path display.
        """
        b  = self.c(Color.BOLD)
        cy = self.c(Color.CYAN)
        r  = self.c(Color.RESET)

        self._write(f"\n{b}Available Templates ({len(templates)}){r}\n")

        current_cat = None
        for path in templates:
            rel = path.relative_to(templates_dir)
            cat = str(rel.parent) if str(rel.parent) != "." else "root"
            if cat != current_cat:
                current_cat = cat
                self._write(f"  {cy}{cat}/{r}")
            self._write(f"    {rel.name}")

        self.blank()

    def template_detail(self, meta: dict):
        """
        Print detailed template information.

        Args:
            meta: Template metadata dictionary.
        """
        b  = self.c(Color.BOLD)
        d  = self.c(Color.DIM)
        cy = self.c(Color.CYAN)
        r  = self.c(Color.RESET)

        sev = meta.get("severity", "info")
        sc  = self.c(Color.SEVERITY.get(sev, ""))

        self._write(f"\n  {b}{meta.get('name', '?')}{r}")
        self._write(f"  {d}{'\u2500' * 40}{r}")
        self._write(f"    {d}ID{r}         {meta.get('id', '?')}")
        self._write(f"    {d}Severity{r}   {sc}{sev.upper()}{r}")

        tags = meta.get("tags", [])
        if tags:
            self._write(f"    {d}Tags{r}       {cy}{', '.join(tags)}{r}")

        desc = meta.get("description", "")
        if desc:
            self._write(f"    {d}About{r}      {desc}")

        author = meta.get("author", "")
        if author:
            self._write(f"    {d}Author{r}     {author}")

        self.blank()

    def validation_result(
        self, rel_path, passed: bool,
        sig_id: str = "", error: str = "", details: list | None = None,
    ):
        """
        Print a single template validation result.

        Args:
            rel_path: Relative path of the template.
            passed: Whether the template passed validation.
            sig_id: Signature ID (shown on success).
            error: Error message (shown on failure).
            details: Additional error details.
        """
        g  = self.c(Color.GREEN)
        rd = self.c(Color.RED)
        d  = self.c(Color.DIM)
        r  = self.c(Color.RESET)

        if passed:
            self._write(f"  {g}OK{r}    {rel_path} {d}({sig_id}){r}")
        else:
            self._write(f"  {rd}FAIL{r}  {rel_path}")
            if error:
                self._write(f"        {error}: {details or []}")

    def validation_summary(self, passed: int, failed: int):
        """
        Print template validation totals.

        Args:
            passed: Number of templates that passed.
            failed: Number of templates that failed.
        """
        b  = self.c(Color.BOLD)
        g  = self.c(Color.GREEN)
        rd = self.c(Color.RED)
        r  = self.c(Color.RESET)
        self._write(
            f"\n{b}Results:{r} {g}{passed} passed{r}, "
            f"{rd}{failed} failed{r}\n"
        )

    def _format_extract(self, extracted: dict) -> str:
        """
        Format extraction data into a compact inline string.

        Args:
            extracted: Dictionary of extracted key-value pairs.

        Returns:
            Formatted string or empty string if no data.
        """
        if not extracted:
            return ""
        d = self.c(Color.DIM)
        r = self.c(Color.RESET)
        parts = []
        for key, vals in extracted.items():
            if vals:
                val = str(vals[0]) if isinstance(vals, list) else str(vals)
                if len(val) > 60:
                    val = val[:57] + "..."
                parts.append(f"{key}: {val}")
        return f" {d}({', '.join(parts)}){r}" if parts else ""
