# Security Policy

## Supported versions

Only the latest commit on the `main` branch receives security fixes.

| Version | Supported |
| ------- | --------- |
| `main` (latest) | Yes |
| Older commits / forks | No |

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Report privately through GitHub:
<https://github.com/heydrsubha-del/SMART-INDIA-HACKATHON-PROJECT-26106/security/advisories/new>

Please include:

- Affected file(s) or module(s) and the commit or version
- Steps to reproduce, and a minimal sample if possible
- Impact (what an attacker could read, change or bypass)
- Any suggested fix

Use synthetic or redacted emails in reports. Never attach real credentials, OAuth client secrets, API keys, Supabase keys, or real user email content.

## Response targets

| Stage | Target |
| ----- | ------ |
| Acknowledgement | 3 business days |
| Initial assessment | 7 days |
| Fix or mitigation for confirmed issues | 30 days (critical issues prioritised) |

You will be kept informed of progress. Credit is given in the advisory unless you prefer to stay anonymous.

## Scope

In scope:

- Email parsing and analysis (header analysis, IOC extraction, scoring, verdict logic)
- Authentication/trust handling (e.g. forged `Authentication-Results`)
- HTML/markdown/report injection (XSS) in the Streamlit UI and exports
- Google/Microsoft OAuth and Supabase contribution flows
- Secret or personal-data exposure, including in logs and reports
- Unintended outbound network access from analysis code

Out of scope:

- Findings that require a compromised host or already-leaked credentials
- Denial of service through unrealistically large inputs on a local single-user run
- Vulnerabilities in third-party services or dependencies with no impact on this project (report those upstream)
- Social engineering of maintainers

## Safe harbour

Good-faith research that follows this policy, avoids privacy violations and service disruption, and does not touch other people's data will not be pursued legally. Test only against your own instance, never against production data or other users' Supabase rows.

## Handling secrets

If you find a committed secret, report it privately as above. Do not use it. The owner will rotate it.
