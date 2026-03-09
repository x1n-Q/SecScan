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
