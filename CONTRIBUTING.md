# Contributing to SecScan

Thanks for helping improve SecScan.

## Before You Contribute

- keep changes focused and easy to review
- open an issue first for large features or major behavior changes
- read `README.md`, `SECURITY.md`, and `RISK_REVIEW.md`
- do not submit changes intended for abuse, stealth, credential capture, persistence, or unauthorized scanning

## Development Setup

```bash
git clone <your-fork-or-repo-url>
cd secscan_gui
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\activate
```

Linux or macOS:

```bash
source .venv/bin/activate
```

Install the project:

```bash
pip install -e .
```

Optional extras:

```bash
pip install -e ".[scanners]"
```

## Recommended Fork Workflow

1. fork the repository on GitHub
2. clone your fork locally
3. create a new branch for your change
4. make and test your change
5. commit with a clear message
6. push to your fork
7. open a pull request

Example:

```bash
git clone https://github.com/<your-user>/secscan_gui.git
cd secscan_gui
git checkout -b fix/improve-docs
```

Then:

```bash
git add .
git commit -m "docs: improve setup and safety guidance"
git push origin fix/improve-docs
```

## What We Welcome

- documentation improvements
- bug fixes
- better result normalization
- better UX in the GUI
- safer defaults and clearer warnings
- support for additional defensive scanners

## What We Will Reject

- code for stealth, evasion, or persistence
- credential theft or token harvesting
- unauthorized exploitation workflows
- features that hide attribution or ownership of scans
- malware behavior or post-exploitation capability
- changes that make active scanning run silently against third-party targets by default

## Coding Expectations

- keep functions small and readable
- match the existing code style
- avoid unrelated refactors
- document user-facing behavior changes in `README.md`
- explain security-sensitive logic clearly in the pull request

## Pull Request Checklist

- change is scoped to one clear purpose
- docs are updated when behavior changes
- no secrets or tokens are committed
- no unrelated generated files are added
- security-sensitive changes are justified in the PR description

## Reporting Bugs

When opening an issue, include:

- what happened
- what you expected
- steps to reproduce
- OS and Python version
- logs or screenshots when useful

## Reporting Security Issues

Do not open a public issue for a security vulnerability. Use the process in `SECURITY.md`.
