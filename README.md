# PhishGuard Triage

![tests](https://github.com/YOUR_USERNAME/phishguard/actions/workflows/tests.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**An offline phishing awareness & red-flag analysis toolkit.**
Built as Project 3 (Detection Phase) of the DecodeLabs Cybersecurity
Industrial Training Kit — *Phishing Awareness Analysis*.

PhishGuard Triage takes a single reported email (`.eml`) or plain-text
message (SMS/chat export) and, with zero network access, tells you:

- **Is it safe, suspicious, or malicious?** (0–100 risk score)
- **Why?** — a categorized, evidence-backed list of red flags
- **What do I do next?** — a concrete action: `Close`, `Warn User`, or
  `Block Domain & Escalate`

---

## Table of Contents

- [Overview](#overview)
- [Detection Capabilities](#detection-capabilities)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Sample Output](#sample-output)
- [Testing](#testing)
- [Configuration](#configuration)
- [Technologies Used](#technologies-used)
- [Threat Model](#threat-model)
- [Roadmap](#roadmap)

---

## Overview

Roughly 80% of security breaches trace back to phishing, and the average
attacker needs under two minutes from send to first click. PhishGuard
Triage operationalizes the "human firewall" concept: it's the tool a Tier-1
SOC analyst (or a trained employee) reaches for when someone forwards a
"is this real?" email.

The engine is fully **static and offline** — it never fetches a URL,
resolves DNS, or executes an attachment. Every finding comes from parsing
headers, text, and link structure locally, which makes it safe to run
directly against real-world malicious samples during training.

## Detection Capabilities

| Signal | What it catches |
|---|---|
| Sender/Display-name spoofing | Brand name in the `From` display name that doesn't match the real sending domain |
| Reply-To mismatch (BEC) | Replies silently rerouted to a different domain than the visible sender |
| Typosquatting & combosquatting | `amaz0n.com`, `paypal-secure-verify.top`, etc. via edit-distance + token analysis |
| Homoglyph domains | Cyrillic/Greek lookalike characters substituted into a domain |
| Nested subdomain traps | A trusted brand buried as a fake subdomain in front of the real root domain |
| IP-literal URLs | Links pointing straight at an IP address instead of a domain |
| URL shorteners & high-risk TLDs | Known shorteners and abuse-heavy TLDs (`.top`, `.click`, `.zip`, ...) |
| Dangerous attachments | `.exe`, `.js`, `.scr`, `.iso`, `.hta`, and other high-risk extensions |
| Cognitive-trigger language | Urgency, authority, fear/greed, and secrecy/bypass phrasing |
| Sensitive-info requests | Password, OTP/MFA, wire transfer, bank/card detail requests |

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for full in-/out-of-scope
details and design assumptions.

## Project Structure

```
phishguard/
├── main.py                    # Entry point (python main.py analyze ...)
├── requirements.txt
├── .gitignore
├── config/
│   └── rules.yaml             # Keyword lexicons, brand list, scoring weights — tune without touching code
├── src/
│   ├── analyzer.py            # Email/text parsing + red-flag detection
│   ├── url_inspector.py       # Typosquat / homoglyph / subdomain-trap / TLD logic
│   ├── risk_scorer.py         # Findings -> score -> verdict -> action
│   ├── report.py              # Color-coded console output + JSON/Markdown reports
│   ├── cli.py                 # Argument parsing & orchestration
│   └── utils.py               # Config loader, Levenshtein distance, safe logging
├── data/samples/               # Mock safe + malicious messages for demo/testing
├── tests/
│   └── test_analyzer.py       # Unit + end-to-end tests
├── docs/
│   └── THREAT_MODEL.md
├── logs/                       # Rotating application log (metadata only, never full bodies)
└── reports/                     # Generated JSON/Markdown analysis reports
```

## Installation

Requires Python 3.10+.

```bash
git clone <your-repo-url>
cd phishguard
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Pushing this project to GitHub

The repo already has an initial `git commit` locally. To publish it:

```bash
# Create an empty repo on GitHub first (no README/license — this project already has both), then:
git remote add origin https://github.com/YOUR_USERNAME/phishguard.git
git branch -M main
git push -u origin main
```

Update the badge URL near the top of this README (replace `YOUR_USERNAME`)
once pushed — GitHub Actions will then automatically run the test suite
on every push/PR via `.github/workflows/tests.yml`.

## Usage

```bash
# Quick console analysis
python main.py analyze data/samples/phishing_sample_1.eml

# Also write a JSON + Markdown report to ./reports/
python main.py analyze data/samples/phishing_sample_2.eml --format all

# Analyze a plain-text SMS/smishing export
python main.py analyze data/samples/smishing_sample_1.txt

# Point at a custom rules file (e.g. tenant-specific brand list)
python main.py analyze suspicious.eml --config config/rules.yaml --outdir reports/
```

**Exit codes** (CI/automation friendly): `0` = SAFE, `1` = SUSPICIOUS, `2` = MALICIOUS.

## Sample Output

```
==============================================================
  PhishGuard Triage Report
==============================================================
  Source     : phishing_sample_1.eml
  Subject    : URGENT: Immediate Wire Transfer Authorization Required
  From       : CEO Name <ceo.name@gmail.com>
==============================================================
  Risk Score : 98/100   Verdict: MALICIOUS   Action: Block Domain & Escalate
==============================================================
  Findings (7):

  [1] Medium   (reply_to_mismatch)
      -> Reply-To address ('finance-urgent@executive-update.com') routes
         replies to a different domain than the visible sender ('gmail.com').
      Evidence: Reply-To: finance-urgent@executive-update.com

  [6] High     (typosquat_domain)
      -> Domain combines brand name 'paypal' with extra words
         (combosquatting) in 'paypal-secure-verify.top'.
      Evidence: URL: https://paypal-secure-verify.top/wire
  ...
==============================================================
```

(Console output is color-coded — green/yellow/red by verdict and severity —
the above is the plain-text rendering.)

## Testing

16 unit + end-to-end tests validate the engine against both mock malicious
payloads (BEC wire-transfer scam, credential-harvesting + malicious
attachment, smishing) and mock safe payloads (internal project update,
team newsletter) to prove out-of-the-box detection accuracy and guard
against false positives.

```bash
pip install pytest
python -m pytest tests/ -v
```

## Configuration

All detection lexicons, the trusted-brand list, and scoring weights live in
[`config/rules.yaml`](config/rules.yaml) — no code changes needed to:

- Add new trusted brands to protect
- Add newly observed phishing keywords/phrases
- Re-tune category weights or SAFE/SUSPICIOUS/MALICIOUS thresholds

## Technologies Used

- **Python 3** (`email`, `argparse`, `dataclasses`, `re`, `logging` — stdlib-first)
- **PyYAML** — external configuration
- **Colorama** — cross-platform color-coded CLI output
- **pytest / unittest** — test suite

## Threat Model

Full scope, detection coverage, and explicit limitations are documented in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Roadmap

- [ ] Public Suffix List integration for precise eTLD+1 extraction
- [ ] Batch-mode analysis for an entire mailbox export
- [ ] Optional SOAR/webhook integration for the "Escalate" action
- [ ] Web UI wrapper around the existing CLI engine
