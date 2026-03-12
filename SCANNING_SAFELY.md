# Scanning Safely

SecScan should only be used for authorized defensive work.

## Allowed Use

- assets you own
- labs and classroom environments with permission
- contracted or internal testing with written approval

## Do Not Scan

- third-party infrastructure without authorization
- public targets just because they are reachable
- production systems unless the owner approved timing and scope

## Before Running Active Scanners

Confirm all of the following:

- you know who owns the target
- you have written permission or internal approval
- the target scope is documented
- the testing window is approved
- you have a rollback or incident contact if something goes wrong

## Target Validation

SecScan now validates target URLs before scanning and warns when a hostname or IP appears external or public.

That warning is a reminder, not permission.

## Rate Limiting

Active scanners are throttled with brief delays between runs to reduce accidental noisy behavior.

This is only a safeguard. It does not make unauthorized scanning acceptable.

## Gitleaks - Secrets Scanning

Gitleaks scans your repository for accidentally committed secrets (API keys, tokens, passwords, etc.).

### Important Safety Notes:

1. **Gitleaks scans your own code** - not external targets
2. **Raw reports are automatically masked** - secrets are replaced with `****` before saving
3. **Secrets are never printed in full** - only the first 4 characters + mask are shown
4. **If secrets are found:**
   - Rotate the credential immediately
   - Remove from source code
   - Rewrite git history with `git-filter-repo`
   - Notify team members

### How to Fix Exposed Secrets:

```bash
# 1. Install git-filter-repo
pip install git-filter-repo

# 2. Remove secret from history
git filter-repo --invert-paths --path <file-with-secret>

# 3. Force push (WARNING: affects all contributors)
git push origin --force-with-lease

# 4. Rotate the credential everywhere
# Change API key, password, token in all systems
```

References:
- [GitHub: Removing sensitive data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)

---

## Public Repository Samples

The sample target under `samples/all-tools-target` is committed with synthetic placeholders only. Those values are intentionally safe to publish and should not be replaced with provider-shaped tokens before pushing to GitHub.

If you want local-only positive Gitleaks findings, create an ignored `.env.local` file in the sample directory and keep it out of commits.

---

## Audit Trail

Each scan writes a `scan_audit.log` file under the scan output directory with:

- timestamp
- project path
- target URL
- selected tools
- scan source (`cli` or `gui`)

## Useful References

- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- GitHub Acceptable Use Policies: https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies

## Liability Reminder

You are responsible for complying with laws, contracts, school rules, workplace policies, and platform rules before scanning any target.
