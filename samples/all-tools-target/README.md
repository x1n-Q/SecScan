# All Tools Target

This sample repository is designed to make the non-website SecScan scanners
applicable from one folder.

It includes markers for:

- Python (`Bandit`, `pip-audit`, `Safety`)
- Node.js (`npm audit`, `CycloneDX SBOM`)
- Go (`govulncheck`)
- Rust (`cargo-audit`)
- PHP (`Composer Audit`)
- Ruby (`bundler-audit`)
- Multi-ecosystem dependency scanners (`OWASP Dependency-Check`, `OSV-Scanner`, `Grype`)
- Code and secrets scanners (`Semgrep`, `Gitleaks`)
- Container and IaC scanners (`Trivy`, `Checkov`)

Notes:

- Website-driven tools still need a target URL and are intentionally not covered here.
- On Windows, `Kube-bench` and `Lynis` remain unavailable because those tools are
  platform-constrained in SecScan.
- Some dependency scanners work best when the ecosystem package manager has already
  restored dependencies or refreshed lockfiles. This target is primarily for
  applicability and UI testing, not guaranteed findings from every scanner.
- All committed secret-looking values in this sample are synthetic placeholders
  chosen to stay safe for a public GitHub repository.
- If you want local-only positive Gitleaks results, create an ignored
  `.env.local` file in this directory instead of committing provider-shaped
  tokens.
