# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ThreatScope, please report it responsibly:

1. **Do NOT** open a public issue
2. Email: [Create a private security advisory](https://github.com/0xsabry/ThreatScope/security/advisories/new)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Scope

ThreatScope is a **log analysis tool** — it processes potentially malicious log data. Security concerns include:

- Regex Denial of Service (ReDoS) in detection patterns
- Path traversal via file loading
- Code injection via crafted log content
- Arbitrary file write via export features

## Response

We aim to:

- Acknowledge reports within 48 hours
- Provide a fix within 7 days for critical issues
- Credit reporters in the changelog (unless anonymity is requested)
