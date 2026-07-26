"""
Core phishing-analysis engine.

Parses a raw email (.eml) or a plain-text message (SMS/chat export pasted as
.txt), extracts structural + textual signals, and produces a list of
`Finding` objects consumed by the risk scorer and report generator.

Design notes:
- No network access, no remote fetching of links, no execution of
  attachments. This is strictly a static, offline triage tool.
- Parsing failures are caught and surfaced as a single clear Finding rather
  than raising a raw traceback that could leak local file-path info.
"""

from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from email.message import Message
from email.utils import parseaddr
from pathlib import Path
from typing import Dict, List, Optional

from . import url_inspector
from .utils import safe_str


@dataclass
class Finding:
    category: str          # matches a key in config scoring_weights
    severity_label: str     # e.g. "High", "Medium", "Low", "Info"
    description: str
    evidence: str = ""


@dataclass
class ParsedMessage:
    subject: str = ""
    from_display_name: str = ""
    from_address: str = ""
    reply_to_address: str = ""
    return_path_address: str = ""
    body_text: str = ""
    attachment_filenames: List[str] = field(default_factory=list)
    raw_source_type: str = "text"  # "eml" or "text"


SEVERITY_BY_CATEGORY_HINT = {
    "dangerous_attachment": "High",
    "homoglyph_domain": "High",
    "subdomain_trap": "High",
    "ip_literal_url": "High",
    "typosquat_domain": "High",
    "sender_domain_mismatch": "High",
    "reply_to_mismatch": "Medium",
    "url_shortener": "Medium",
    "suspicious_tld": "Medium",
    "sensitive_info_request": "Medium",
    "secrecy_bypass_language": "Medium",
    "urgency_language": "Low",
    "authority_language": "Low",
    "fear_greed_language": "Low",
    "display_name_spoof": "High",
}


def _extract_domain(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower()


def parse_eml(raw_bytes: bytes) -> ParsedMessage:
    msg: Message = email.message_from_bytes(raw_bytes)
    parsed = ParsedMessage(raw_source_type="eml")

    parsed.subject = safe_str(msg.get("Subject", ""), max_len=300)

    display_name, from_addr = parseaddr(msg.get("From", ""))
    parsed.from_display_name = safe_str(display_name, max_len=150)
    parsed.from_address = safe_str(from_addr.lower(), max_len=200)

    _, reply_to = parseaddr(msg.get("Reply-To", ""))
    parsed.reply_to_address = safe_str(reply_to.lower(), max_len=200)

    _, return_path = parseaddr(msg.get("Return-Path", ""))
    parsed.return_path_address = safe_str(return_path.lower(), max_len=200)

    body_parts: List[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            if filename:
                parsed.attachment_filenames.append(safe_str(filename, max_len=200))
                continue

            content_type = part.get_content_type()
            if content_type in ("text/plain", "text/html") and "attachment" not in content_disposition:
                try:
                    payload = part.get_payload(decode=True) or b""
                    charset = part.get_content_charset() or "utf-8"
                    body_parts.append(payload.decode(charset, errors="replace"))
                except (LookupError, ValueError):
                    body_parts.append("")
    else:
        try:
            payload = msg.get_payload(decode=True) or b""
            charset = msg.get_content_charset() or "utf-8"
            body_parts.append(payload.decode(charset, errors="replace"))
        except (LookupError, ValueError):
            body_parts.append(str(msg.get_payload()))

    # Strip a light amount of HTML to plain-ish text for keyword scanning.
    combined = "\n".join(body_parts)
    combined = re.sub(r"<[^>]+>", " ", combined)
    parsed.body_text = safe_str(combined, max_len=20000)

    return parsed


def parse_plaintext(raw_text: str) -> ParsedMessage:
    """
    Handle pasted SMS/chat/plain messages that have no formal headers.
    Attempts a light heuristic extraction of a 'From:' style line if present,
    otherwise treats the whole input as body text (e.g. an SMS/smishing text).
    """
    parsed = ParsedMessage(raw_source_type="text")
    lines = raw_text.splitlines()

    header_pattern = re.compile(r"^(From|Subject|Reply-To)\s*:\s*(.*)$", re.IGNORECASE)
    body_start = 0
    for i, line in enumerate(lines[:15]):
        match = header_pattern.match(line.strip())
        if match:
            key, value = match.group(1).lower(), match.group(2).strip()
            if key == "from":
                display_name, addr = parseaddr(value)
                parsed.from_display_name = safe_str(display_name or value, max_len=150)
                parsed.from_address = safe_str(addr.lower(), max_len=200)
            elif key == "subject":
                parsed.subject = safe_str(value, max_len=300)
            elif key == "reply-to":
                _, addr = parseaddr(value)
                parsed.reply_to_address = safe_str(addr.lower(), max_len=200)
            body_start = i + 1
        else:
            break

    parsed.body_text = safe_str("\n".join(lines[body_start:]) or raw_text, max_len=20000)
    return parsed


def load_message(path: Path) -> ParsedMessage:
    """Dispatch to the correct parser based on file extension / content sniff."""
    suffix = path.suffix.lower()
    raw_bytes = path.read_bytes()

    if suffix == ".eml":
        return parse_eml(raw_bytes)

    text = raw_bytes.decode("utf-8", errors="replace")
    # Sniff: if it looks like a real email (has From:/Subject: headers plus
    # blank-line body separation), parse as eml; else treat as plain text.
    if re.search(r"(?im)^From:.*@", text) and re.search(r"(?im)^Subject:", text):
        return parse_eml(raw_bytes)
    return parse_plaintext(text)


def _keyword_hits(body_lower: str, keywords: List[str]) -> List[str]:
    return [kw for kw in keywords if kw.lower() in body_lower]


class PhishingAnalyzer:
    """Runs the full red-flag detection suite against a ParsedMessage."""

    def __init__(self, config: Dict):
        self.config = config

    def analyze(self, parsed: ParsedMessage) -> List[Finding]:
        findings: List[Finding] = []
        body_lower = parsed.body_text.lower()

        findings.extend(self._check_sender_identity(parsed))
        findings.extend(self._check_language_triggers(body_lower))
        findings.extend(self._check_attachments(parsed))
        findings.extend(self._check_urls(parsed.body_text))

        return findings

    # ------------------------------------------------------------------ #
    # Sender / header analysis
    # ------------------------------------------------------------------ #
    def _check_sender_identity(self, parsed: ParsedMessage) -> List[Finding]:
        findings: List[Finding] = []
        trusted_brands = self.config.get("trusted_brands", [])
        freemail_domains = self.config.get("freemail_domains", [])

        from_domain = _extract_domain(parsed.from_address)
        display_lower = parsed.from_display_name.lower()

        # Display name impersonates a trusted brand, but the actual sending
        # domain is an unrelated freemail / non-brand domain.
        impersonated_brand = next((b for b in trusted_brands if b in display_lower), None)
        if impersonated_brand:
            domain_matches_brand = impersonated_brand in from_domain
            if not domain_matches_brand:
                if from_domain in freemail_domains:
                    findings.append(Finding(
                        category="sender_domain_mismatch",
                        severity_label=SEVERITY_BY_CATEGORY_HINT["sender_domain_mismatch"],
                        description=(
                            f"Display name references '{impersonated_brand}' but the message "
                            f"actually originates from a free/consumer email domain "
                            f"('{from_domain}'), not an official '{impersonated_brand}' domain."
                        ),
                        evidence=f"From: {parsed.from_display_name} <{parsed.from_address}>",
                    ))
                else:
                    findings.append(Finding(
                        category="display_name_spoof",
                        severity_label=SEVERITY_BY_CATEGORY_HINT["display_name_spoof"],
                        description=(
                            f"Display name references '{impersonated_brand}' but the sending "
                            f"domain ('{from_domain}') does not match that brand."
                        ),
                        evidence=f"From: {parsed.from_display_name} <{parsed.from_address}>",
                    ))

        # Reply-To silently redirects responses to a different domain than
        # the visible From address -- a classic BEC / spoofing indicator.
        if parsed.reply_to_address:
            reply_domain = _extract_domain(parsed.reply_to_address)
            if reply_domain and from_domain and reply_domain != from_domain:
                findings.append(Finding(
                    category="reply_to_mismatch",
                    severity_label=SEVERITY_BY_CATEGORY_HINT["reply_to_mismatch"],
                    description=(
                        f"Reply-To address ('{parsed.reply_to_address}') routes replies to a "
                        f"different domain than the visible sender ('{from_domain}')."
                    ),
                    evidence=f"Reply-To: {parsed.reply_to_address}",
                ))

        return findings

    # ------------------------------------------------------------------ #
    # Social-engineering / cognitive-trigger language
    # ------------------------------------------------------------------ #
    def _check_language_triggers(self, body_lower: str) -> List[Finding]:
        findings: List[Finding] = []

        checks = [
            ("urgency_keywords", "urgency_language", "urgency/time-pressure language"),
            ("authority_keywords", "authority_language", "authority-impersonation language"),
            ("fear_greed_keywords", "fear_greed_language", "fear or reward-based manipulation language"),
            ("sensitive_info_keywords", "sensitive_info_request", "a request for sensitive/credential information"),
            ("secrecy_bypass_keywords", "secrecy_bypass_language", "instructions to bypass normal verification or keep the request secret"),
        ]

        for config_key, category, label in checks:
            keywords = self.config.get(config_key, [])
            hits = _keyword_hits(body_lower, keywords)
            if hits:
                findings.append(Finding(
                    category=category,
                    severity_label=SEVERITY_BY_CATEGORY_HINT.get(category, "Low"),
                    description=f"Message contains {label}.",
                    evidence="Matched phrase(s): " + ", ".join(sorted(set(hits))[:5]),
                ))
        return findings

    # ------------------------------------------------------------------ #
    # Attachments
    # ------------------------------------------------------------------ #
    def _check_attachments(self, parsed: ParsedMessage) -> List[Finding]:
        findings: List[Finding] = []
        dangerous_ext = self.config.get("dangerous_attachment_extensions", [])

        for filename in parsed.attachment_filenames:
            lower_name = filename.lower()
            for ext in dangerous_ext:
                if lower_name.endswith(ext):
                    findings.append(Finding(
                        category="dangerous_attachment",
                        severity_label=SEVERITY_BY_CATEGORY_HINT["dangerous_attachment"],
                        description=(
                            f"Attachment '{filename}' uses a high-risk executable/script "
                            f"extension ('{ext}')."
                        ),
                        evidence=f"Attachment: {filename}",
                    ))
                    break
        return findings

    # ------------------------------------------------------------------ #
    # URLs / domains
    # ------------------------------------------------------------------ #
    def _check_urls(self, body_text: str) -> List[Finding]:
        findings: List[Finding] = []
        url_findings = url_inspector.analyze_urls(body_text, self.config)

        for uf in url_findings:
            for issue, category in zip(uf.issues, uf.severity_categories):
                findings.append(Finding(
                    category=category,
                    severity_label=SEVERITY_BY_CATEGORY_HINT.get(category, "Medium"),
                    description=issue,
                    evidence=f"URL: {uf.url}",
                ))
        return findings
