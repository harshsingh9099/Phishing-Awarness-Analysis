"""
Command-line interface for PhishGuard Triage.

Usage:
    python main.py analyze <path-to-email-or-text-file> [options]

This module intentionally contains no business logic -- it only parses
arguments, wires the analyzer/scorer/report modules together, and handles
top-level error presentation (never leaking raw stack traces to the user).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from colorama import Fore, Style

from .analyzer import PhishingAnalyzer, load_message
from .report import build_report_dict, print_console_report, write_json_report, write_markdown_report
from .risk_scorer import score_findings
from .utils import DEFAULT_CONFIG_PATH, get_logger, load_config

logger = get_logger()

MAX_INPUT_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB guardrail against resource-exhaustion


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="PhishGuard Triage -- offline phishing awareness & red-flag analysis toolkit.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a single email/message file.")
    analyze_parser.add_argument("input_file", type=str, help="Path to a .eml or .txt message file.")
    analyze_parser.add_argument(
        "--format", choices=["console", "json", "markdown", "all"], default="console",
        help="Output format. 'console' prints only; others also write a report file.",
    )
    analyze_parser.add_argument(
        "--outdir", type=str, default="reports",
        help="Directory to write JSON/Markdown reports into (default: ./reports).",
    )
    analyze_parser.add_argument(
        "--config", type=str, default=str(DEFAULT_CONFIG_PATH),
        help="Path to a custom rules.yaml configuration file.",
    )

    return parser


def _validate_input_path(raw_path: str) -> Path:
    path = Path(raw_path).expanduser().resolve()

    if not path.exists():
        raise SystemExit(f"{Fore.RED}Error: input file not found.{Style.RESET_ALL}")
    if not path.is_file():
        raise SystemExit(f"{Fore.RED}Error: input path is not a file.{Style.RESET_ALL}")
    if path.suffix.lower() not in (".eml", ".txt"):
        raise SystemExit(
            f"{Fore.RED}Error: unsupported file type '{path.suffix}'. "
            f"Use .eml or .txt.{Style.RESET_ALL}"
        )
    if path.stat().st_size > MAX_INPUT_SIZE_BYTES:
        raise SystemExit(f"{Fore.RED}Error: input file exceeds the 5 MB safety limit.{Style.RESET_ALL}")

    return path


def run_analyze(args: argparse.Namespace) -> int:
    try:
        input_path = _validate_input_path(args.input_file)
        config = load_config(args.config)
    except RuntimeError as exc:
        print(f"{Fore.RED}Configuration error: {exc}{Style.RESET_ALL}")
        return 2

    try:
        parsed = load_message(input_path)
    except Exception:
        # Never surface raw parser exceptions (could contain memory addresses,
        # local paths, etc.) -- log full detail server-side only.
        logger.exception("Failed to parse input file: %s", input_path.name)
        print(f"{Fore.RED}Error: could not parse the input file. It may be malformed. "
              f"See logs/phishguard.log for details.{Style.RESET_ALL}")
        return 3

    analyzer = PhishingAnalyzer(config)
    findings = analyzer.analyze(parsed)
    result = score_findings(findings, config)

    logger.info(
        "Analyzed '%s' -> score=%s verdict=%s findings=%s",
        input_path.name, result.score, result.verdict, len(findings),
    )

    print_console_report(parsed, result, source_name=input_path.name)

    if args.format in ("json", "markdown", "all"):
        report_dict = build_report_dict(parsed, result, input_path.name)
        outdir = Path(args.outdir)
        base_name = f"{input_path.stem}_report"

        if args.format in ("json", "all"):
            json_path = write_json_report(report_dict, outdir, base_name)
            print(f"{Fore.CYAN}JSON report written to: {json_path}{Style.RESET_ALL}")
        if args.format in ("markdown", "all"):
            md_path = write_markdown_report(report_dict, outdir, base_name)
            print(f"{Fore.CYAN}Markdown report written to: {md_path}{Style.RESET_ALL}")

    # Exit codes make this CI/automation friendly: 0 safe, 1 suspicious, 2 malicious.
    return {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}[result.verdict]


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        return run_analyze(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
