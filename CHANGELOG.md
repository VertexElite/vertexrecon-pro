# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Initial public release of the Vertex Recon Pro toolkit.
- `vertex-net` (Go): `/proc/net` connection analysis, concurrent port scanning
  with banner grabbing, DNS + TLS recon, HTTP security-header auditing, malware
  IOC domain checks, `/proc` network deep scan, live connection monitor, and IP
  reputation lookups.
- `vertex-sys` (Rust): ELF header parsing, Shannon entropy analysis with 4KB
  block breakdown, suspicious-string extraction, filesystem anomaly scanning,
  and hidden/suspicious process detection.
- `vertex-osint` (Ruby): crt.sh subdomain enumeration, WAF/CDN + framework
  fingerprinting, TLS/certificate analysis, IP/ASN intelligence, Wayback
  history, and JSON + HTML report generation.
- `vertex-pattern` (OCaml): file-magic identification, hex pattern search,
  per-block entropy mapping, malware signature scanning, and hex dumps.
- `build.sh` multi-language builder with Termux auto-install support.
- Project docs: `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `.gitignore`,
  and CI workflow.

### Fixed
- `vertex-sys`: corrected the entropy value formatting in `elf-scan` output
  (was printing a literal `:.4` instead of rounding to 4 decimal places).
