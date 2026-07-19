<div align="center">

```
╦  ╦╔═╗╦═╗╔╦╗╔═╗═╗ ╦  ╔═╗╦═╗╔═╗
╚╗╔╝║╣ ╠╦╝ ║ ║╣ ╔╩╦╝  ╠═╝╠╦╝║ ║
 ╚╝ ╚═╝╩╚═ ╩ ╚═╝╩ ╚═  ╩  ╩╚═╚═╝
```

# Vertex Recon Pro

**A multi-language security & reconnaissance toolkit for Termux / Linux.**

Defensive analysis · threat hunting · authorized security assessment

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux-informational.svg)](#requirements)
![Languages](https://img.shields.io/badge/languages-Go%20%7C%20Rust%20%7C%20Ruby%20%7C%20OCaml-orange.svg)
[![Use: Authorized only](https://img.shields.io/badge/use-authorized%20only-red.svg)](SECURITY.md)

</div>

---

> [!WARNING]
> This toolkit performs active network scanning, reconnaissance, and binary
> analysis. Use it **only** against systems you own or are explicitly authorized
> to test. See [SECURITY.md](SECURITY.md) and the [legal notice](#-legal--ethical-use).

## Table of Contents

- [Overview](#overview)
- [Components](#components)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Build](#build)
- [Usage](#usage)
  - [vertex-net (Go)](#vertex-net--go)
  - [vertex-sys (Rust)](#vertex-sys--rust)
  - [vertex-osint (Ruby)](#vertex-osint--ruby)
  - [vertex-pattern (OCaml)](#vertex-pattern--ocaml)
- [Reports](#reports)
- [Legal & ethical use](#-legal--ethical-use)
- [Contributing](#contributing)
- [License](#license)

## Overview

Vertex Recon Pro is four focused tools, each written in the language best
suited to the job, unified by a single build script and a shared visual style.
The emphasis throughout is **defensive**: surfacing suspicious connections,
flagging known malware indicators, auditing a target's exposed security
posture, and inspecting binaries for signs of packing or tampering.

Nothing here plants, persists, or exfiltrates. Every tool reads state and
reports on it.

## Components

| Tool             | Lang  | Focus | Highlights |
|------------------|-------|-------|------------|
| **`vertex-net`**     | Go    | Network recon | `/proc/net` connection analysis, concurrent port scanning w/ banner grab, DNS + TLS recon, HTTP security-header auditing, malware **IOC** domain checks, live connection monitor |
| **`vertex-sys`**     | Rust  | System inspection | ELF header parsing, Shannon **entropy** analysis (packed/encrypted detection), `strings` w/ threat keywords, filesystem anomaly scan, **hidden-process** detection |
| **`vertex-osint`**   | Ruby  | OSINT | crt.sh **subdomain** enumeration, WAF/CDN + tech fingerprinting, TLS/cert analysis, IP/ASN intel, Wayback history, **JSON + HTML report** generation |
| **`vertex-pattern`** | OCaml | Binary forensics | File-magic identification, **hex pattern** search, per-block entropy map, malware **signature scanning** (shellcode, webshells, CS beacons), hex dumps |

## Repository layout

```
vertexrecon-pro/
├── build.sh                 # Builds / links all components into ./bin
├── go/
│   └── vertex-net.go        # Go network recon engine
├── rust/
│   ├── Cargo.toml           # crate: vertex-sys
│   └── src/main.rs          # Rust system inspector
├── ruby/
│   └── vertex-osint.rb      # Ruby OSINT engine
├── ocaml/
│   └── vertex_pattern.ml    # OCaml binary pattern matcher
├── README.md
├── SECURITY.md              # Responsible-use policy + reporting
├── CONTRIBUTING.md
├── CHANGELOG.md
└── LICENSE                  # GPL-3.0
```

## Requirements

| Component | Needs |
|-----------|-------|
| `vertex-net`     | Go (`golang`) |
| `vertex-sys`     | Rust + Cargo (`rust`) |
| `vertex-osint`   | Ruby (`ruby`) — stdlib only, no gems |
| `vertex-pattern` | OCaml + `ocamlfind`/`ocamlopt` and the `str` library (`ocaml`) |

On **Termux** the build script installs anything missing via `pkg`. `vertex-net`
(Go), `vertex-sys` (Rust) and `vertex-osint` (Ruby) build/run natively. OCaml
isn't in the main Termux repo — it lives in the **TUR** — so if `vertex-pattern`
is skipped, add it with:

```bash
pkg install tur-repo && pkg install ocaml
./build.sh ocaml
```

The build script now attempts this automatically and skips `vertex-pattern`
gracefully (the other three tools still build) if OCaml can't be installed.

On a regular Linux distro, install the toolchains with your package manager first.

## Build

`build.sh` compiles each component, links the Ruby script, and drops everything
into `./bin/` (offering to add it to your `PATH`):

```bash
./build.sh          # build everything
./build.sh go       # or build one component: go | rust | ocaml | ruby
```

Then, after `source ~/.bashrc` (or running the binaries from `./bin/` directly):

```bash
vertex-net --help
```

## Usage

### `vertex-net` — Go

```bash
vertex-net conns              # Deep /proc/net connection analysis
vertex-net scan <host>        # Concurrent port scan (top ~1000) + banner grab
vertex-net dns <domain>       # A/AAAA/MX/NS/TXT/CNAME + reverse DNS + TLS cert
vertex-net headers <url>      # HTTP security-header audit + info-leak check
vertex-net ioc                # Check known malware IOC domains
vertex-net proc               # ARP / routes / iface stats / socket stats
vertex-net monitor            # Live new-connection monitor (Ctrl+C to stop)
vertex-net lookup <ip>        # IP reputation / geo lookup (ipinfo.io)
vertex-net full <domain>      # Run the whole suite against a target
```

### `vertex-sys` — Rust

```bash
vertex-sys entropy <file>     # Shannon entropy + 4KB block analysis
vertex-sys elf-scan <dir>     # Recursively find & profile ELF binaries
vertex-sys strings <file> [n] # Extract strings (min len n), flag suspicious
vertex-sys proc               # Hidden / suspicious process detection
vertex-sys anomaly <dir>      # Hidden execs + recently-modified files
vertex-sys full               # Run all system checks
```

### `vertex-osint` — Ruby

```bash
vertex-osint full <domain>    # All modules + JSON/HTML report
vertex-osint subs <domain>    # crt.sh subdomain enumeration + resolution
vertex-osint headers <domain> # Security-header grade (A–F) + cookie analysis
vertex-osint tech <domain>    # WAF/CDN + framework fingerprinting
vertex-osint tls <domain>     # Protocol/cipher/cert/SAN/chain analysis
vertex-osint ip <domain>      # IP + ASN/org intelligence
vertex-osint wayback <domain> # Wayback Machine snapshot history
```

### `vertex-pattern` — OCaml

```bash
vertex-pattern analyze <file>          # Full binary analysis (all of the below)
vertex-pattern entropy <file>          # Per-block entropy map
vertex-pattern threats <file>          # Malware signature scan
vertex-pattern hex <file> <hexpattern> # Search for a raw hex pattern
vertex-pattern identify <file>         # File-type identification by magic bytes
```

## Reports

- `vertex-osint` writes JSON + a dark-themed HTML report to
  `~/vertex-recon-logs/osint/<domain>_<timestamp>.{json,html}`.
- Build artifacts land in `./bin/`.

Both locations are git-ignored.

## ⚠️ Legal & Ethical Use

This toolkit is intended for **defensive security, threat hunting, education,
and authorized penetration testing only**.

- Active scanning, port scanning, subdomain enumeration, and any recon against
  a target must be performed **only** on systems you **own** or have **explicit,
  written permission** to test.
- Unauthorized scanning or access may be **illegal** in your jurisdiction
  (e.g. the US CFAA, the UK Computer Misuse Act, and equivalents worldwide).
- You are solely responsible for how you use these tools. The authors and
  contributors accept **no liability** for misuse or damage.

If you're not sure you're authorized, **you're not authorized.** See
[SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for coding
style, the build/lint expectations per language, and the responsible-use
ground rules for new detection features.

## License

Distributed under the **GNU GPL v3.0**. See [LICENSE](LICENSE).
