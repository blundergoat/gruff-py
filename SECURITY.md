# Security Policy

## Supported Versions

`0.1.x` is the current supported release line. Security fixes target the latest
`0.1.x` release and the `main` branch.

## Reporting A Vulnerability

Do not open a public issue for a suspected vulnerability.

If this repository is published under an organisation, use the organisation's
private security advisory flow or the maintainer contact listed on the package
metadata.

Include:

- affected version or commit
- reproduction steps
- expected impact
- whether a token, secret, or private source file was involved

## Scope

In scope:

- executing unexpected code during analysis
- unsafe handling of local files
- report or dashboard injection
- secret exposure in findings or logs
- path traversal in the local dashboard

Out of scope:

- false positives or false negatives from heuristic rules
- findings intentionally emitted from files the user asked gruff-py to scan
- risks caused by manually binding the dashboard to a shared network interface

## Dashboard Note

`gruff-py dashboard` has no authentication and is intended for local
development. It binds to `127.0.0.1` by default. Do not expose it on a shared
network unless you understand the risk.

