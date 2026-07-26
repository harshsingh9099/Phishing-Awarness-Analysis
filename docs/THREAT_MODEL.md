# Threat Model -- PhishGuard Triage

## Scope

PhishGuard Triage is a **static, offline, non-expert-friendly triage tool**
for the detection phase of phishing awareness. It analyzes a single message
(`.eml` or plain-text export) and answers three questions:

1. Is this message suspicious?
2. Which specific signals (red flags) make it suspicious?
3. What should a non-expert employee do about it right now?

It is explicitly **not** a mail-server filter, sandbox, or SOC-grade EDR
integration -- it is a decision-support and training artifact that mirrors
how a Tier-1 analyst would triage a reported email.

## In-Scope Threats (Detection Coverage)

| Threat Category | Technique Detected |
|---|---|
| Display-name spoofing | Trusted brand name in `From` display name, mismatched actual domain |
| Business Email Compromise (BEC) | Reply-To routing to a different domain than the visible sender |
| Typosquatting | Domain within small edit-distance of a trusted brand (`amaz0n.com`) |
| Combosquatting | Trusted brand name glued to extra words (`paypal-secure-verify.top`) |
| Homoglyph attacks | Cyrillic/Greek lookalike characters substituted into a domain |
| Nested subdomain traps | Brand name buried as a fake subdomain in front of the real root domain |
| IP-literal URLs | Links pointing directly to a raw IP address instead of a domain |
| URL shorteners | Known shortening services that obscure the real destination |
| Suspicious TLDs | High-abuse top-level domains (`.top`, `.click`, `.zip`, etc.) |
| Dangerous attachments | Executable/script file extensions (`.exe`, `.js`, `.scr`, `.iso`, ...) |
| Cognitive-trigger language | Urgency, authority, fear/greed, and secrecy-bypass phrasing |
| Sensitive-info harvesting | Requests for passwords, OTP/MFA codes, wallet/bank details |

## Out of Scope (By Design)

- **Live URL fetching / sandbox detonation.** The tool never contacts a
  link or opens an attachment -- all analysis is static text/metadata
  parsing, so it is safe to run directly against real malicious samples.
- **DNS/WHOIS/reputation lookups.** No network calls are made at all
  (fully offline-capable), so results are based purely on structural and
  linguistic heuristics rather than live threat intelligence.
- **Deepfake audio/video analysis, voice biometrics.** Out of scope for a
  text/metadata-based tool; mentioned in the accompanying awareness
  materials but not automatable here.
- **Blocking or remediation actions.** The tool *recommends* an action
  (Close / Warn User / Block Domain & Escalate) but does not execute it --
  a human or a separate SOAR integration performs the actual block.

## Assumptions & Limitations

- Detection relies on curated keyword/brand lists in `config/rules.yaml`;
  it will not catch novel social-engineering phrasing that isn't
  represented there. Extend the lists as new campaigns are observed.
- Root-domain extraction uses a simplified "last two labels" heuristic
  rather than a full Public Suffix List, which can misclassify some
  multi-part TLDs (e.g. `.co.uk`). Acceptable for a lightweight triage
  tool; flagged here for transparency.
- This tool produces a **risk score and recommendation**, not a
  definitive verdict. Final human judgment and the organization's
  reporting workflow should always be the last step (see the "Pause,
  Verify, Report" model referenced in the training material).
