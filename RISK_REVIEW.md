# Repository Risk Review

This file answers a practical question: could this repository be seen as risky by a hosting platform, school, employer, or security program?

## Short Answer

Probably **yes, it can attract scrutiny**, because it includes active scanning and recon capability.

It does **not** currently look like malware or credential-stealing code, but it does contain offensive-security style tooling and wrappers that could be misunderstood or considered high-risk depending on the platform rules and how the repo is presented.

## Why It Can Look Risky

The codebase includes wrappers or built-in logic for:

- SQL injection testing
- port scanning
- directory and sensitive path discovery
- reflected XSS probing
- web vulnerability scanning
- subdomain reconnaissance

Those are normal in authorized security work, but they are also the exact categories that can trigger policy review if the repo is described or used carelessly.

## Files to Review Carefully

- `secscan/tools/sqlmap.py`
- `secscan/tools/nmap.py`
- `secscan/tools/dirb.py`
- `secscan/tools/nikto.py`
- `secscan/tools/xsspy.py`
- `secscan/tools/zap.py`
- `secscan/tools/amass_scan.py`
- `secscan/tools/__init__.py`

## What I Did Not Find

I did not find code that appears to implement:

- ransomware behavior
- botnet control
- password theft
- keylogging
- browser cookie theft
- persistence installation
- hidden remote shells
- destructive wiping behavior

## Credential Handling Note

The GitHub import helper should avoid embedding personal access tokens in clone URLs or saved remote URLs.

File:

- `secscan/core/github_repo.py`

Why this matters:

- the token can appear in local process arguments while the git command is running
- local monitoring tools or process viewers may expose it

The safer pattern is to keep the remote URL clean and provide credentials only for the active Git operation.

## How To Lower Platform Risk

- keep the authorized-use warning prominent in `README.md`
- avoid language like "attack", "exploit anything", or "stealth"
- document that web and network checks require permission
- keep risky scanners clearly opt-in
- reject contributions that add exfiltration, persistence, or stealth
- avoid bundling live target lists, leaked credentials, or bypass content

## Practical Bottom Line

If you keep this repo framed as an authorized defensive scanner, it is much safer.

If you market or modify it as a tool for unauthorized recon, scanning, or exploitation, that is where the real risk of account, platform, school, or employer trouble starts.
