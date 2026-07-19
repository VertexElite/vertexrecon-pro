# Contributing to Vertex Recon Pro

Thanks for your interest in improving the toolkit! A few ground rules keep this
project useful and safe.

## Ground rules

- **Defensive scope only.** New features should help operators *detect,
  analyze, or audit* — not attack. Pull requests that add exploitation,
  payload delivery, C2 functionality, persistence, or exfiltration will be
  declined. See [SECURITY.md](SECURITY.md).
- **Authorized-use framing.** Anything that performs active scanning should be
  clearly documented as requiring authorization.
- **No secrets or live targets.** Don't commit API keys, tokens, personal data,
  or real victim/customer hostnames. Detection signatures and public IOC
  references are fine; live credentials are not.

## Project layout

Each language lives in its own directory (`go/`, `rust/`, `ruby/`, `ocaml/`) and
builds into `./bin/` via `build.sh`. Keep components self-contained — the
shared "contract" is only the CLI subcommand style and the ANSI color palette.

## Style & checks per language

Please make sure your change at least builds/parses before opening a PR:

| Language | Format | Build / lint |
|----------|--------|--------------|
| Go       | `gofmt -w go/`           | `go vet ./...`, `go build ./...` |
| Rust     | `cargo fmt`              | `cargo build --release`, `cargo clippy` |
| Ruby     | 2-space indent           | `ruby -c ruby/vertex-osint.rb` |
| OCaml    | `ocamlformat` (optional) | `ocamlfind ocamlopt -package str -linkpkg ocaml/vertex_pattern.ml` |

- Prefer the **standard library**; avoid pulling in heavy dependencies. Ruby is
  currently gem-free and Go is module-free by design.
- Match the existing output style (section banners, `[✓]/[!]/[→]` prefixes,
  the color constants defined at the top of each file).

## Commit & PR

1. Fork and branch from the default branch.
2. Keep commits focused and messages descriptive.
3. Describe **what** the change detects/adds and **why** it's defensive.
4. Note any new outbound network calls or files written to disk.

## Reporting bugs

Open an issue with the component, command, expected vs. actual behavior, and
your platform (Termux / distro + arch). For **security** issues in the toolkit
itself, follow [SECURITY.md](SECURITY.md) instead of the public tracker.
