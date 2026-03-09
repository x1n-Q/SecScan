# SecScan

SecScan is a Python desktop and CLI application for scanning software projects and web targets with a mix of dependency, code, secrets, infrastructure, and optional web-security checks.

## Authorized Use Only

Use this project only for:

- learning in a lab or classroom environment
- scanning your own systems
- security testing with explicit written permission

Do not use SecScan against systems, applications, APIs, domains, or networks you do not own or have authorization to assess.

## What It Does

- detects project languages, frameworks, and dependency files
- runs multiple security tools from one GUI or CLI workflow
- normalizes findings into one result format
- exports JSON and HTML reports
- tracks scan history and basic scoring
- supports optional GitHub repository import for local scanning

## Included Scanner Types

### Software and supply chain

- `npm audit`
- `OWASP Dependency-Check`
- `OSV-Scanner`
- `Grype`
- `pip-audit`
- `Safety`
- `CycloneDX SBOM`

### Code, secrets, containers, and IaC

- `Semgrep`
- `Bandit`
- `Gitleaks`
- `Trivy`
- `Checkov`
- `Kube-bench`
- `Lynis`

### Web, recon, and network

- `Security Headers`
- `TLS Certificate Check`
- `OWASP ZAP`
- `Nikto`
- `Dirb`
- `Nmap`
- `Sqlmap`
- `XssPy`
- `Amass`

## High-Risk Features

Some scanners in this repo perform active probing or reconnaissance. These are the parts most likely to raise policy, hosting, or acceptable-use concerns if misused:

- `Sqlmap` for SQL injection testing
- `Nmap` for port and service scanning
- `Nikto` and `Dirb` style web probing
- `XssPy` reflected XSS probes
- `OWASP ZAP` active web scanning
- `Amass` passive recon against domains

If you are publishing or forking this project, make the authorized-use warning visible and avoid marketing it for abuse, bypass, exploitation, credential theft, or stealth.

## Platform Policy Compliance

This project includes active security scanners. GitHub and other platforms prohibit using any tool for unauthorized access attempts or abusive scanning.

**Allowed:**
- scanning systems you own
- authorized penetration testing with written permission
- lab or classroom environments with permission

**Prohibited:**
- scanning third-party infrastructure without authorization
- using the tool for credential theft, exfiltration, disruption, or stealth
- bypassing authentication or access controls without approval

See `SCANNING_SAFELY.md` and `DANGEROUS_SCANNERS.md` before enabling active scanners.

## Quick Start

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd secscan_gui
```

### 1b. Download with PowerShell (`iwr`)

If someone does not have Git installed, they can download the repository ZIP from GitHub with PowerShell:

```powershell
iwr https://github.com/x1n-Q/SecScan/archive/refs/heads/main.zip -OutFile SecScan.zip
Expand-Archive .\SecScan.zip -DestinationPath .
cd .\SecScan-main
```

### 2. Create and activate a virtual environment

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install the package

```bash
pip install -e .
```

Optional scanner extras:

```bash
pip install -e ".[scanners]"
```

## How to Use It

### GUI

```bash
python -m secscan.main
```

Typical GUI flow:

1. select a local project folder, or import a GitHub repository
2. optionally enter a website URL for web checks
3. choose a scan mode
4. run the scan
5. review findings and export reports

For GitHub imports, personal access tokens are intended only for the active clone or pull operation and should not be committed, shared, or stored in repository remotes.

Active scanners such as `Sqlmap`, `Nmap`, `OWASP ZAP`, `Nikto`, `Dirb`, `XssPy`, and `Amass` require explicit manual opt-in in the GUI and an extra confirmation before they run.

### CLI

List available tools:

```bash
python -m secscan.cli list-tools
```

Run a local project scan:

```bash
python -m secscan.cli scan --repo ./my-project --profile "Recommended Scan" --format both
```

Run a web-focused scan:

```bash
python -m secscan.cli scan --repo ./my-project --url https://example.com --profile "Web Scan" --allow-active-scans --format json
```

Run the full profile:

```bash
python -m secscan.cli scan --repo ./my-project --url https://example.com --profile "Full Scan" --allow-active-scans --format both
```

## Scan Profiles

- `Quick Scan` - fast dependency and secret checks
- `Recommended Scan` - a safer default for most project reviews
- `Full Scan` - every available scanner that applies
- `Web Scan` - focused on web, recon, and network checks

## Output Layout

Results are written under:

```text
<target-project>/secscan-results/
  raw/
  findings.json
  report.html
```

History is stored under:

```text
<target-project>/.secscan-history/
```

## Forking This Repository

If you want your own copy on GitHub:

1. click **Fork** on GitHub
2. clone your fork locally
3. create a feature branch
4. make your changes
5. push the branch to your fork
6. open a pull request back to the main repository

Example:

```bash
git clone https://github.com/<your-user>/secscan_gui.git
cd secscan_gui
git checkout -b docs/update-project-docs
```

After making changes:

```bash
git add .
git commit -m "docs: improve project policies and usage guide"
git push origin docs/update-project-docs
```

## Contributing

See `CONTRIBUTING.md` for:

- local setup
- branch and pull request workflow
- how to propose changes
- contribution boundaries for security-sensitive code

## Security

See `SECURITY.md` for:

- how to report vulnerabilities
- supported versions
- safe testing rules
- prohibited contribution categories

## Safe Scanning Guides

- `SCANNING_SAFELY.md` - target authorization, validation, and handling guidance
- `DANGEROUS_SCANNERS.md` - scanners that require explicit authorization and when to avoid them

## Repository Risk Review

See `RISK_REVIEW.md` for a direct assessment of whether this repo contains code likely to trigger platform or abuse concerns.

## License

This project is licensed under the MIT License. See `LICENSE`.

## Disclaimer

This software is provided "as is" without warranty. You are responsible for complying with laws, contracts, platform policies, and authorization requirements before running any scan.
