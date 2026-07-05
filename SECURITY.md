# Security Policy

## Reporting a Vulnerability

Please report security issues privately via **GitHub Security Advisories**
(Security → Report a vulnerability) on this repository, or email
aiken@megapower.asia. Do not open public issues for security reports.

We aim to acknowledge reports within 72 hours. Fixes for confirmed issues in
the core hashing/verification path are treated as highest priority across all
four language implementations simultaneously.

## Scope

- Hash generation / verification correctness (Argon2id, PHC parsing, policy)
- Downgrade or DoS vectors via crafted encoded hashes
- Timing side channels in tag comparison
- Reason-code or error-path information leaks (passwords/salts/tags must never leak)

## Supported Versions

Only the latest released MINOR of each package receives security fixes.
