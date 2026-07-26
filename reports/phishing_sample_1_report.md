# PhishGuard Triage Report

**Source:** phishing_sample_1.eml  
**Generated (UTC):** 2026-07-26T16:40:44.941558+00:00

## Message Summary
- **Subject:** URGENT: Immediate Wire Transfer Authorization Required
- **From:** CEO Name <ceo.name@gmail.com>
- **Reply-To:** finance-urgent@executive-update.com
- **Attachments:** 0 (none)

## Risk Assessment
- **Score:** 98/100
- **Verdict:** MALICIOUS
- **Recommended Action:** Block Domain & Escalate

## Findings

### 1. [Medium] reply_to_mismatch
- **Description:** Reply-To address ('finance-urgent@executive-update.com') routes replies to a different domain than the visible sender ('gmail.com').
- **Evidence:** `Reply-To: finance-urgent@executive-update.com`

### 2. [Low] urgency_language
- **Description:** Message contains urgency/time-pressure language.
- **Evidence:** `Matched phrase(s): immediately`

### 3. [Low] authority_language
- **Description:** Message contains authority-impersonation language.
- **Evidence:** `Matched phrase(s): ceo, strictly confidential`

### 4. [Medium] sensitive_info_request
- **Description:** Message contains a request for sensitive/credential information.
- **Evidence:** `Matched phrase(s): wire transfer`

### 5. [Medium] secrecy_bypass_language
- **Description:** Message contains instructions to bypass normal verification or keep the request secret.
- **Evidence:** `Matched phrase(s): do not discuss`

### 6. [High] typosquat_domain
- **Description:** Domain combines brand name 'paypal' with extra words (combosquatting) in 'paypal-secure-verify.top'.
- **Evidence:** `URL: https://paypal-secure-verify.top/wire`

### 7. [Medium] suspicious_tld
- **Description:** Domain uses a high-abuse top-level domain ('paypal-secure-verify.top').
- **Evidence:** `URL: https://paypal-secure-verify.top/wire`
