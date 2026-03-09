# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| older versions | No |

## Reporting a Vulnerability

Please do not report security vulnerabilities in public issues.

Use one of these private channels instead:

- GitHub Security Advisories, if enabled for the repository
- direct maintainer contact, if listed in the repository profile

Include:

- a clear description of the issue
- affected version or commit
- impact and likely severity
- steps to reproduce
- logs, proof of concept, or screenshots if needed

## Response Targets

- initial acknowledgment within 72 hours
- first triage decision within 7 days
- remediation timing depends on severity and complexity

## Safe Testing Rules

Test only on:

- your own systems
- isolated labs
- environments where you have explicit permission

Do not use this project to scan or probe third-party infrastructure without authorization.

## Repository Abuse Boundary

This repository includes code that can run active security checks. To keep the project on the defensive side of the line, maintainers should reject contributions that add or normalize:

- credential theft
- spyware or keylogging
- persistence or lateral movement
- exploit chaining for unauthorized access
- covert exfiltration
- stealth, anti-forensics, or attribution removal
- default scanning of arbitrary internet targets without user intent

## Known Operational Risk Areas

The most sensitive parts of this repository are the active web and network scanners, including wrappers for `Sqlmap`, `Nmap`, `OWASP ZAP`, and the built-in `Dirb`, `Nikto`, and `XssPy` style checks.

These features are useful in authorized testing, but they should be documented carefully and kept opt-in.

## Secrets Handling

Never commit:

- personal access tokens
- API keys
- session cookies
- scan targets that are confidential
- raw reports containing customer secrets

If a secret is accidentally committed, rotate it immediately and remove it from follow-up history where possible.
