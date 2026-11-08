# Security Policy

## Reporting a vulnerability

Please do not open a public issue. Report privately via GitHub's
"Report a vulnerability" (Security tab -> Advisories) on
`dzaczek/metriccupid-push`, or by email to sirjacek@gmail.com.

Include the affected version, a description, and steps to reproduce.
You should get a reply within 7 days.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope: authentication bypass, replay, rate-limit/ban bypass, client IP
spoofing, leaking of secrets or message contents (responses or logs),
memory-exhaustion or crash bugs reachable by unauthenticated clients.

Out of scope: volumetric DDoS against an origin exposed without a proxy
(put Cloudflare or a Tunnel in front, see README), and issues that require
access to the relay's environment or `RELAY_SECRETS`.
