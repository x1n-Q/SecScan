# Dangerous Scanners

These scanners can send active requests, enumerate services, or probe for vulnerabilities. Use them only with explicit authorization.

## `Sqlmap`

- Purpose: SQL injection testing
- Risk: can send aggressive payloads to application parameters
- Use only when: the target owner approved SQL injection testing
- Avoid when: you do not control the target or do not know the impact tolerance

## `Nmap`

- Purpose: port and service scanning
- Risk: can trigger monitoring, alerting, or policy review
- Use only when: network discovery is explicitly in scope
- Avoid when: public or third-party infrastructure is not approved

## `OWASP ZAP`

- Purpose: active web vulnerability scanning
- Risk: spiders and probes many endpoints automatically
- Use only when: web application testing is authorized
- Avoid when: change-sensitive production systems are not approved

## `Nikto`

- Purpose: web server misconfiguration and exposure checks
- Risk: probes known sensitive paths and methods
- Use only when: server-level testing is in scope
- Avoid when: you are unsure whether the target is externally monitored

## `Dirb`

- Purpose: directory and path discovery
- Risk: enumerates endpoints that may be sensitive or noisy
- Use only when: content discovery is approved
- Avoid when: the target owner did not approve discovery testing

## `XssPy`

- Purpose: reflected XSS probing
- Risk: injects probe payloads into request parameters
- Use only when: the target owner approved application security testing
- Avoid when: you do not have approval for input manipulation tests

## `Amass`

- Purpose: subdomain reconnaissance
- Risk: expands the visible attack surface of a domain
- Use only when: recon for that domain is explicitly authorized
- Avoid when: the domain is not yours or not in scope

## General Rule

If you are asking yourself whether you are allowed to run one of these scanners, stop and get written authorization first.
