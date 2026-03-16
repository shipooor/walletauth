# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `@walletauth/server`, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, use [GitHub's private vulnerability reporting](https://github.com/walletauth/server/security/advisories/new). You can also DM [@shipooor](https://x.com/shipooor) on X.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix release**: as soon as possible, depending on severity

## Scope

The following are in scope:
- Signature verification bypass
- Challenge forgery or replay attacks
- JWT token forgery or algorithm confusion
- Timing attacks on HMAC or signature comparison
- Denial of service via crafted inputs (ReDoS, CPU exhaustion)
- Information leakage through error messages or timing

The following are out of scope:
- Rate limiting (explicitly not built-in, documented as API owner's responsibility)
- Transport security (HTTPS enforcement is the deployer's responsibility)
- Secret management (storing/rotating secrets is the deployer's responsibility)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
