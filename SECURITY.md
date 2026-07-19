# Security Policy & Responsible Use

Vertex Recon Pro is a **defensive** security toolkit. This document covers both
how to use it responsibly and how to report a vulnerability in the toolkit
itself.

## Authorized use only

The tools in this repository perform active network scanning, reconnaissance,
and binary analysis. By using them you agree that you will:

1. **Only** target systems you own or for which you hold **explicit written
   authorization** (e.g. a signed penetration-testing engagement, a bug-bounty
   scope, a CTF you're registered for, or your own lab).
2. Respect the scope and rules of engagement you've been given — including
   rate limits, out-of-scope hosts, and disclosure timelines.
3. Comply with all applicable laws. Unauthorized scanning or access can be a
   criminal offense (e.g. the US **CFAA**, the UK **Computer Misuse Act 1990**,
   the EU directives, and equivalents elsewhere).

If you do not have authorization, **do not run these tools against the target.**

## What this toolkit does *not* do

To be explicit, this project intentionally contains **no** offensive payloads:

- No exploitation, no reverse shells, no C2 client/implant.
- No persistence, privilege escalation, or credential harvesting.
- No exfiltration.

The malware "signatures", "IOC domains", and "C2 ports" that appear in the code
are **detection references** — patterns the tools *look for* in order to flag
suspicious activity. They are not used to attack anything.

## Data & privacy

- `vertex-net` and `vertex-osint` make outbound requests to third-party
  services (`ipinfo.io`, `crt.sh`, `web.archive.org`) as part of recon. Be
  aware that the targets you query are visible to those services.
- `vertex-osint` writes reports containing your findings to
  `~/vertex-recon-logs/`. Treat those reports as sensitive.

## Reporting a vulnerability in Vertex Recon Pro

If you find a security issue **in this toolkit's own code** (for example, a way
it could be abused to harm the operator, or a memory-safety bug):

1. **Do not** open a public issue with exploit details.
2. Open a private report via GitHub's **Security → Report a vulnerability**
   (GitHub Security Advisories) on this repository, or contact the maintainer
   directly.
3. Please include reproduction steps, affected component/version, and impact.

We aim to acknowledge reports within a reasonable time and will credit
reporters who wish to be named.

## Supported versions

This is an actively developed toolkit; fixes land on the default branch. Pin to
a tagged release if you need stability.
