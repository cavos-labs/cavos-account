# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (main) | Yes |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing **security@cavos.xyz**. Include:

1. Description of the vulnerability
2. Steps to reproduce or proof-of-concept
3. Potential impact
4. Any suggested mitigations

You will receive a response within 48 hours. We will work with you to understand and resolve the issue before any public disclosure.

## Scope

In-scope vulnerabilities include:

- Logic errors in `cavos_account.cairo` (authentication bypass, session key theft, spending policy bypass)
- Cryptographic weaknesses in JWT verification or nonce computation
- Reentrancy or storage collision issues
- Incorrect RSA/Garaga integration allowing signature forgery

Out-of-scope:

- Issues in third-party dependencies (Garaga, StarkNet stdlib) — report those upstream
- Theoretical attacks requiring compromised OAuth providers (Google/Apple)
- Gas griefing / DoS that only affects the caller's own account
