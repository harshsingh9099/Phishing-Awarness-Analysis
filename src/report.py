"""
Report generation: color-coded console summary + exportable JSON/Markdown
analysis reports for the triage toolkit.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from colorama import Fore, Style, init as colorama_init

from .analyzer import ParsedMessage
from .risk_scorer import RiskResult

colorama_init(autoreset=True)

VERDICT_COLORS = {
    "SAFE": Fore.GREEN,
    "SUSPICIOUS": Fore.YELLOW,
    "MALICIOUS": Fore.RED,
}

SEVERITY_COLORS = {
    "High": Fore.RED,
    "Medium": Fore.YELLOW,
    "Low": Fore.CYAN,
    "Info": Fore.WHITE,
}


def print_console_report(parsed: ParsedMessage, result: RiskResult, source_name: str) -> None:
    color = VERDICT_COLORS.get(result.verdict, Fore.WHITE)
    bar = "=" * 62

    print(f"\n{Style.BRIGHT}{bar}")
    print(f"  PhishGuard Triage Report")
    print(f"{bar}{Style.RESET_ALL}")
    print(f"  Source     : {source_name}")
    print(f"  Subject    : {parsed.subject or '(none)'}")
    print(f"  From       : {parsed.from_display_name} <{parsed.from_address or 'unknown'}>")
    print(f"{Style.BRIGHT}{bar}{Style.RESET_ALL}")
    print(
        f"  Risk Score : {color}{result.score}/100{Style.RESET_ALL}   "
        f"Verdict: {color}{Style.BRIGHT}{result.verdict}{Style.RESET_ALL}   "
        f"Action: {color}{result.action}{Style.RESET_ALL}"
    )
    print(f"{bar}")

    if not result.findings:
        print(f"  {Fore.GREEN}No red flags detected.{Style.RESET_ALL}")
    else:
        print(f"  Findings ({len(result.findings)}):\n")
        for idx, finding in enumerate(result.findings, start=1):
            sev_color = SEVERITY_COLORS.get(finding.severity_label, Fore.WHITE)
            print(f"  [{idx}] {sev_color}{finding.severity_label:<8}{Style.RESET_ALL} "
                  f"({finding.category})")
            print(f"      -> {finding.description}")
            if finding.evidence:
                print(f"      Evidence: {finding.evidence}")
            print()

    print(f"{bar}\n")


def build_report_dict(parsed: ParsedMessage, result: RiskResult, source_name: str) -> Dict:
    return {
        "source": source_name,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "message": {
            "subject": parsed.subject,
            "from_display_name": parsed.from_display_name,
            "from_address": parsed.from_address,
            "reply_to_address": parsed.reply_to_address,
            "attachment_count": len(parsed.attachment_filenames),
            "attachments": parsed.attachment_filenames,
        },
        "risk": {
            "score": result.score,
            "verdict": result.verdict,
            "recommended_action": result.action,
        },
        "findings": [asdict(f) for f in result.findings],
    }


def write_json_report(report_dict: Dict, outdir: Path, base_name: str) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / f"{base_name}.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report_dict, fh, indent=2)
    return out_path


def write_markdown_report(report_dict: Dict, outdir: Path, base_name: str) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / f"{base_name}.md"

    msg = report_dict["message"]
    risk = report_dict["risk"]

    lines = [
        f"# PhishGuard Triage Report",
        "",
        f"**Source:** {report_dict['source']}  ",
        f"**Generated (UTC):** {report_dict['generated_at_utc']}",
        "",
        "## Message Summary",
        f"- **Subject:** {msg['subject'] or '(none)'}",
        f"- **From:** {msg['from_display_name']} <{msg['from_address'] or 'unknown'}>",
        f"- **Reply-To:** {msg['reply_to_address'] or '(none)'}",
        f"- **Attachments:** {msg['attachment_count']} "
        f"({', '.join(msg['attachments']) if msg['attachments'] else 'none'})",
        "",
        "## Risk Assessment",
        f"- **Score:** {risk['score']}/100",
        f"- **Verdict:** {risk['verdict']}",
        f"- **Recommended Action:** {risk['recommended_action']}",
        "",
        "## Findings",
    ]

    if not report_dict["findings"]:
        lines.append("\nNo red flags detected.")
    else:
        for i, f in enumerate(report_dict["findings"], start=1):
            lines.append(f"\n### {i}. [{f['severity_label']}] {f['category']}")
            lines.append(f"- **Description:** {f['description']}")
            if f["evidence"]:
                lines.append(f"- **Evidence:** `{f['evidence']}`")

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    return out_path
