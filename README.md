# Vertex Recon Pro

A multi-language security & reconnaissance toolkit built for **Termux / Linux**.
Each component is written in a different language, chosen for what it does best,
and all of them are geared toward **defensive analysis, threat hunting, and
authorized security assessment**.

```
╦  ╦╔═╗╦═╗╔╦╗╔═╗═╗ ╦  ╔═╗╦═╗╔═╗
╚╗╔╝║╣ ╠╦╝ ║ ║╣ ╔╩╦╝  ╠═╝╠╦╝║ ║
 ╚╝ ╚═╝╩╚═ ╩ ╚═╝╩ ╚═  ╩  ╩╚═╚═╝
      Multi-Language Security Toolkit
```

## Components

| Tool             | Language | Purpose |
|------------------|----------|---------|
| `vertex-net`     | Go       | Network recon: `/proc/net` connection analysis, concurrent port scanning, DNS recon, TLS inspection, HTTP security-header auditing, malware IOC domain checks, live connection monitor |
| `vertex-sys`     | Rust     | System-level deep inspection: ELF binary scanning, entropy analysis, `/proc` deep dive, file integrity, hidden-process detection |
| `vertex-osint`   | Ruby     | Intelligence gathering: crt.sh subdomain enumeration, tech fingerprinting, header analysis, WHOIS/ASN correlation, Wayback snapshots, report generation |
| `vertex-pattern` | OCaml    | Binary pattern matching: file-magic signature scanning, hex pattern matching, entropy sectioning, structure-anomaly detection |

## Layout

```
vertexrecon-pro/
├── build.sh              # Builds/links all components into ./bin
├── go/vertex-net.go      # Go network recon engine
├── rust/                 # Rust system inspector (Cargo project)
│   ├── Cargo.toml
│   └── src/main.rs
├── ruby/vertex-osint.rb  # Ruby OSINT engine
└── ocaml/vertex_pattern.ml
```

## Build

The build script installs missing toolchains (via `pkg` on Termux), compiles
each component, and drops the binaries into `./bin/`.

```bash
./build.sh          # build everything
./build.sh go       # or build a single component: go | rust | ocaml | ruby
```

Then either add `./bin` to your `PATH` (the script offers to do this) or call
the binaries directly.

### Requirements

- Go (`golang`)
- Rust + Cargo (`rust`)
- Ruby (`ruby`)
- OCaml + `ocamlfind`/`ocamlopt` and the `str` library (`ocaml`)

## Usage

```bash
vertex-net conns              # Deep connection analysis
vertex-net scan example.com   # Concurrent port scan (top ~1000 ports)
vertex-net dns example.com    # Full DNS recon + TLS cert inspection
vertex-net headers example.com# HTTP security-header audit
vertex-net ioc                # Check known malware IOC domains
vertex-net full example.com   # Run the full suite against a target

vertex-sys proc               # Hidden process detection
vertex-sys elf-scan /sdcard   # Scan a path for ELF binaries

vertex-osint full example.com # Full OSINT recon + report

vertex-pattern analyze /path  # Binary pattern analysis
```

## ⚠️ Legal & Ethical Use

This toolkit is intended for **defensive security, threat hunting, education,
and authorized penetration testing only**. Active scanning, port scanning, and
recon must only be run against systems you **own** or have **explicit written
permission** to test. You are responsible for complying with all applicable
laws. The authors accept no liability for misuse.

## License

See [LICENSE](LICENSE).
