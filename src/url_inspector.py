"""
URL / domain inspection engine.

Implements the visual & structural deception checks called out in the
project brief: typosquatting, homoglyph substitution, combosquatting,
nested-subdomain traps, IP-literal URLs, suspicious TLDs, and shortener
usage. Every function is pure (no network calls) so this tool is safe to
run against live phishing samples without ever contacting attacker
infrastructure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List
from urllib.parse import urlparse

from .utils import levenshtein_distance

# Basic RFC-ish URL matcher; deliberately permissive since phishing URLs
# are often malformed on purpose.
URL_PATTERN = re.compile(
    r"""(?xi)
    \b
    (?:https?://|www\.)
    [^\s<>"'\)\]]+
    """
)

IPV4_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# A small, non-exhaustive homoglyph map covering the most common
# Cyrillic/Greek lookalikes used in real spoofed-domain campaigns.
HOMOGLYPH_CHARS = {
    "а": "a",  # Cyrillic a
    "е": "e",  # Cyrillic e
    "о": "o",  # Cyrillic o
    "р": "p",  # Cyrillic er
    "с": "c",  # Cyrillic es
    "х": "x",  # Cyrillic ha
    "у": "y",  # Cyrillic u
    "і": "i",  # Cyrillic i
    "ѕ": "s",  # Cyrillic dze
    "ᴜ": "u",
    "ⅼ": "l",
}


@dataclass
class UrlFinding:
    url: str
    root_domain: str
    issues: List[str] = field(default_factory=list)
    severity_categories: List[str] = field(default_factory=list)


def extract_urls(text: str) -> List[str]:
    """Pull all candidate URLs out of a body of text."""
    if not text:
        return []
    found = URL_PATTERN.findall(text)
    # Normalize bare "www." matches to have a scheme for urlparse.
    normalized = []
    for u in found:
        u = u.rstrip(".,;:!?")
        if u.startswith("www."):
            u = "https://" + u
        normalized.append(u)
    return list(dict.fromkeys(normalized))  # de-dupe, preserve order


def get_host(url: str) -> str:
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def get_root_domain(host: str) -> str:
    """
    Naive but effective eTLD+1 extraction for common cases
    (does not attempt full public-suffix-list resolution, which is
    intentionally out of scope for a lightweight triage tool).
    """
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def is_ip_literal(host: str) -> bool:
    # Strip brackets for IPv6 literals like [::1]
    candidate = host.strip("[]")
    if IPV4_PATTERN.match(candidate):
        return True
    if candidate.count(":") >= 2:  # crude IPv6 heuristic
        return True
    return False


def contains_homoglyph(host: str) -> bool:
    return any(ch in HOMOGLYPH_CHARS for ch in host)


def deconfuse(host: str) -> str:
    """Map homoglyph characters back to their ASCII lookalike for comparison."""
    return "".join(HOMOGLYPH_CHARS.get(ch, ch) for ch in host)


def check_typosquat(root_domain: str, trusted_brands: List[str], max_distance: int) -> str | None:
    """
    Compare the registrable domain's label against each trusted brand name.
    Returns the matched brand if the domain (or a hyphen/digit-separated
    token within it) is a close-but-not-exact match to a trusted brand --
    e.g. 'amaz0n.com' -> 'amazon', or 'amaz0n-secure.click' -> the token
    'amaz0n' is what actually gets compared, not the whole hyphenated label.
    """
    label = root_domain.split(".")[0] if root_domain else ""
    if not label:
        return None

    # Compare the full label AND each token split on non-alphanumeric
    # separators, so a brand lookalike glued to extra words is still caught.
    candidates = {label} | set(re.split(r"[^a-z0-9]+", label))
    candidates.discard("")

    for candidate in candidates:
        ascii_candidate = deconfuse(candidate)
        for brand in trusted_brands:
            if ascii_candidate == brand:
                continue  # exact legitimate match, not a typosquat
            distance = levenshtein_distance(ascii_candidate, brand)
            if 0 < distance <= max_distance:
                return brand
    return None


def check_combosquat(host: str, trusted_brands: List[str]) -> str | None:
    """
    Detect a trusted brand name bolted onto extra words in the *registrable*
    label, e.g. 'yourcompany-secure-login.com' patterns or 'paypal-verify.com'.
    """
    root = get_root_domain(host)
    label = root.split(".")[0] if root else ""
    for brand in trusted_brands:
        if brand in label and label != brand:
            return brand
    return None


def check_subdomain_trap(host: str, trusted_brands: List[str]) -> str | None:
    """
    Detect a trusted brand name buried as a *subdomain* while the true
    root domain is something else entirely, e.g.
    'www.decodelabs.tech.login-update.com' -> true root is 'login-update.com'.
    """
    root = get_root_domain(host)
    subdomain_portion = host[: -len(root)] if root and host.endswith(root) else host
    for brand in trusted_brands:
        if brand in subdomain_portion and brand not in root:
            return brand
    return None


def analyze_url(url: str, trusted_brands: List[str], shorteners: List[str],
                 suspicious_tlds: List[str], typosquat_max_distance: int) -> UrlFinding:
    host = get_host(url)
    root = get_root_domain(host)
    finding = UrlFinding(url=url, root_domain=root)

    if not host:
        finding.issues.append("Malformed or unparsable URL.")
        return finding

    if is_ip_literal(host):
        finding.issues.append(f"URL uses a raw IP address ({host}) instead of a domain name.")
        finding.severity_categories.append("ip_literal_url")

    if contains_homoglyph(host):
        finding.issues.append(
            f"Domain '{host}' contains non-Latin lookalike characters (homoglyph attack)."
        )
        finding.severity_categories.append("homoglyph_domain")

    typo_brand = check_typosquat(root, trusted_brands, typosquat_max_distance)
    if typo_brand:
        finding.issues.append(
            f"Domain '{root}' closely resembles trusted brand '{typo_brand}' (typosquatting)."
        )
        finding.severity_categories.append("typosquat_domain")

    combo_brand = check_combosquat(host, trusted_brands)
    if combo_brand and not typo_brand:
        finding.issues.append(
            f"Domain combines brand name '{combo_brand}' with extra words "
            f"(combosquatting) in '{root}'."
        )
        finding.severity_categories.append("typosquat_domain")

    trap_brand = check_subdomain_trap(host, trusted_brands)
    if trap_brand:
        finding.issues.append(
            f"Brand name '{trap_brand}' appears as a fake subdomain while the true "
            f"root domain is '{root}' (nested subdomain trap)."
        )
        finding.severity_categories.append("subdomain_trap")

    if any(root == s or host.endswith("." + s) or host == s for s in shorteners):
        finding.issues.append(f"URL uses a link-shortening service ('{host}'), hiding the true destination.")
        finding.severity_categories.append("url_shortener")

    if any(root.endswith(tld) for tld in suspicious_tlds):
        finding.issues.append(f"Domain uses a high-abuse top-level domain ('{root}').")
        finding.severity_categories.append("suspicious_tld")

    return finding


def analyze_urls(text: str, config: Dict) -> List[UrlFinding]:
    urls = extract_urls(text)
    trusted_brands = config.get("trusted_brands", [])
    shorteners = config.get("url_shorteners", [])
    suspicious_tlds = config.get("suspicious_tlds", [])
    max_distance = config.get("typosquat_max_distance", 2)

    return [
        analyze_url(u, trusted_brands, shorteners, suspicious_tlds, max_distance)
        for u in urls
    ]
