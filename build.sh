#!/data/data/com.termux/files/usr/bin/bash
# ═══════════════════════════════════════════════════════════════
#  VERTEX RECON PRO — Multi-Language Security Toolkit
#  Build script for Go, Rust, Ruby, OCaml components
# ═══════════════════════════════════════════════════════════════

set -e
CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; PURPLE='\033[0;35m'; NC='\033[0m'; BOLD='\033[1m'

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
BINDIR="$BASEDIR/bin"
mkdir -p "$BINDIR"

echo -e "${PURPLE}"
echo "  ╦  ╦╔═╗╦═╗╔╦╗╔═╗═╗ ╦  ╔═╗╦═╗╔═╗"
echo "  ╚╗╔╝║╣ ╠╦╝ ║ ║╣ ╔╩╦╝  ╠═╝╠╦╝║ ║"
echo "   ╚╝ ╚═╝╩╚═ ╩ ╚═╝╩ ╚═  ╩  ╩╚═╚═╝"
echo -e "${NC}${CYAN}  Multi-Language Security Toolkit — Builder${NC}"
echo ""

install_if_missing() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "  ${YELLOW}[*]${NC} Installing $1..."
        pkg install -y "$2" 2>/dev/null || {
            echo -e "  ${RED}[!]${NC} Failed to install $2"
            return 1
        }
    fi
    echo -e "  ${GREEN}[✓]${NC} $1 available"
}

build_go() {
    echo -e "\n${CYAN}══ Building Go: vertex-net ══${NC}"
    install_if_missing "go" "golang" || return
    
    cd "$BASEDIR/go"
    
    # Initialize module if needed
    if [ ! -f go.mod ]; then
        go mod init vertex-net
    fi
    
    echo -e "  ${YELLOW}[*]${NC} Compiling..."
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "$BINDIR/vertex-net" vertex-net.go
    echo -e "  ${GREEN}[✓]${NC} Built: $BINDIR/vertex-net"
}

build_rust() {
    echo -e "\n${CYAN}══ Building Rust: vertex-sys ══${NC}"
    install_if_missing "rustc" "rust" || return
    install_if_missing "cargo" "rust" || return
    
    cd "$BASEDIR/rust"
    
    echo -e "  ${YELLOW}[*]${NC} Compiling (release)..."
    cargo build --release 2>&1 | tail -5
    cp target/release/vertex-sys "$BINDIR/"
    echo -e "  ${GREEN}[✓]${NC} Built: $BINDIR/vertex-sys"
}

have_ocaml() {
    command -v ocamlfind &>/dev/null || command -v ocamlopt &>/dev/null || command -v ocamlc &>/dev/null
}

build_ocaml() {
    echo -e "\n${CYAN}══ Building OCaml: vertex-pattern ══${NC}"

    # Get an OCaml toolchain. On Termux, OCaml lives in the TUR (Termux User
    # Repository), not the main repo — so try main first, then enable the TUR.
    if ! have_ocaml; then
        echo -e "  ${YELLOW}[*]${NC} Installing OCaml..."
        pkg install -y ocaml 2>/dev/null \
            || { pkg install -y tur-repo 2>/dev/null && pkg install -y ocaml 2>/dev/null; } \
            || true
    fi

    if ! have_ocaml; then
        echo -e "  ${YELLOW}[!]${NC} OCaml toolchain unavailable — skipping vertex-pattern."
        echo -e "      The other tools still build fine. To add OCaml on Termux:"
        echo -e "        ${BOLD}pkg install tur-repo && pkg install ocaml${NC}"
        echo -e "      then re-run: ${BOLD}./build.sh ocaml${NC}"
        return 0
    fi

    cd "$BASEDIR/ocaml"
    echo -e "  ${YELLOW}[*]${NC} Compiling..."

    local built=""
    # 1) findlib + native  2) native + str  3) bytecode + str (portable fallback)
    if command -v ocamlfind &>/dev/null; then
        if ocamlfind ocamlopt -package str -linkpkg -o "$BINDIR/vertex-pattern" vertex_pattern.ml 2>/dev/null; then built=1; fi
    fi
    if [ -z "$built" ] && command -v ocamlopt &>/dev/null; then
        if ocamlopt -I +str str.cmxa -o "$BINDIR/vertex-pattern" vertex_pattern.ml 2>/dev/null; then built=1; fi
    fi
    if [ -z "$built" ] && command -v ocamlc &>/dev/null; then
        if ocamlc -I +str str.cma -o "$BINDIR/vertex-pattern" vertex_pattern.ml 2>/dev/null; then built=1; fi
    fi

    # Tidy up intermediate artifacts
    rm -f "$BASEDIR"/ocaml/*.cm* "$BASEDIR"/ocaml/*.o 2>/dev/null || true
    cd "$BASEDIR"

    if [ -n "$built" ]; then
        echo -e "  ${GREEN}[✓]${NC} Built: $BINDIR/vertex-pattern"
    else
        echo -e "  ${YELLOW}[!]${NC} OCaml present but compile failed — skipping vertex-pattern."
    fi
}

setup_ruby() {
    echo -e "\n${CYAN}══ Setting up Ruby: vertex-osint ══${NC}"
    install_if_missing "ruby" "ruby" || return
    
    chmod +x "$BASEDIR/ruby/vertex-osint.rb"
    ln -sf "$BASEDIR/ruby/vertex-osint.rb" "$BINDIR/vertex-osint"
    echo -e "  ${GREEN}[✓]${NC} Linked: $BINDIR/vertex-osint"
}

setup_path() {
    echo -e "\n${CYAN}══ PATH Setup ══${NC}"
    
    if ! echo "$PATH" | grep -q "$BINDIR"; then
        echo "export PATH=\"$BINDIR:\$PATH\"" >> ~/.bashrc
        echo "export PATH=\"$BINDIR:\$PATH\"" >> ~/.profile 2>/dev/null
        export PATH="$BINDIR:$PATH"
        echo -e "  ${GREEN}[✓]${NC} Added $BINDIR to PATH"
    else
        echo -e "  ${GREEN}[✓]${NC} Already in PATH"
    fi
}

# ─── Build targets ────────────────────────────────────────────

case "${1:-all}" in
    go)     build_go ;;
    rust)   build_rust ;;
    ocaml)  build_ocaml ;;
    ruby)   setup_ruby ;;
    all)
        build_go
        build_rust
        build_ocaml
        setup_ruby
        setup_path
        
        echo -e "\n${GREEN}══════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  BUILD COMPLETE${NC}"
        echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "  ${BOLD}Binaries in:${NC} $BINDIR/"
        ls -lh "$BINDIR/" 2>/dev/null | tail -n +2 | while read line; do
            echo "    $line"
        done
        echo ""
        echo -e "  ${BOLD}Quick start:${NC}"
        echo "    vertex-net conns              # Deep connection analysis"
        echo "    vertex-net scan example.com   # Concurrent port scan"
        echo "    vertex-net ioc                # Check malware IOC domains"
        echo "    vertex-sys proc               # Hidden process detection"
        echo "    vertex-sys elf-scan /sdcard    # Scan for ELF binaries"
        echo "    vertex-osint full example.com # Full OSINT recon"
        echo "    vertex-pattern analyze /path  # Binary pattern analysis"
        echo ""
        echo -e "  ${YELLOW}Run 'source ~/.bashrc' to refresh PATH${NC}"
        ;;
    *)
        echo "Usage: $0 [go|rust|ocaml|ruby|all]"
        ;;
esac
