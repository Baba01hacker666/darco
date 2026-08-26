# Admin Panel Discovery & Smart Credential Auditing

Darco provides active administrative panel probing and domain-intelligent credential testing via `darco admin` (or `darco admin-finder`).

## Overview

Administrative interfaces and backend management consoles are high-value entry points. `darco admin`:
1. Probes a curated dictionary of administrative paths (`/admin`, `/administrator`, `/wp-admin`, `/backend`, `/cpanel`, `/whm`, `/manager/html`, `/dashboard`, `/phpmyadmin`, `/actuator`, etc.).
2. Classifies the response state:
   - `exposed_dashboard`: HTTP 200 with admin indicators and no login form (unauthenticated dashboard).
   - `login_form`: Discovered an HTML login form with parsed input fields.
   - `basic_auth`: HTTP 401 with `WWW-Authenticate` challenge.
   - `portal_redirect`: HTTP 301/302 redirecting to an auth gate.
   - `forbidden`: HTTP 403 administrative endpoint exists but access is restricted.
3. Automatically generates smart credentials based on the domain name and harvested emails.
4. Performs non-destructive authentication verification and reports results with curl reproduction commands.

## Smart Credential Generation

Unlike static wordlists, `darco` dynamically combines:
- **Standard Administrative Accounts:** `admin`, `administrator`, `root`, `support`, `info`, `security`, `contact`, `staff`, etc.
- **Domain-Specific Emails:** `admin@domain.com`, `root@domain.com`, `support@domain.com`, etc.
- **Discovered Emails:** Passively harvested or crawl-extracted emails (`alice.smith@domain.com` -> `alice.smith`, `alice`).
- **Domain-Derived Passwords:** Combinations of the company/domain name with common suffixes (`domain`, `domain123`, `domain2026`, `domain!`, `domain@123`).

## Usage

```bash
# Discover admin panels on target
darco admin https://target.test

# Provide specific email addresses to test in credentials
darco admin https://target.test --email security@target.test

# Disable default credential testing (discovery only)
darco admin https://target.test --no-default-creds

# Save findings to workspace
darco admin https://target.test --save
```
