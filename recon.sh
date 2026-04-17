#!/bin/bash
# ============================================================
#  recon.sh — Elite Bug Bounty Recon Automation v3
#  Author: Vamsi | OrsuRecon
#  Tested on: WSL Kali Linux, Native Kali Linux, Ubuntu VPS
# ============================================================

set -uo pipefail

# ─── CONFIGURATION ──────────────────────────────────────────
# Discord webhook URL for notifications
DISCORD_WEBHOOK="https://discordapp.com/api/webhooks/1470700740824535081/iQvdpHUBi_ZnCNfPNWiiuZ6vcxihm5dfWn2OTHVJKsdLM4T7smsArRptRnlz0hYYtF4o"
STAGE_TIMEOUT=300
ENABLE_NUCLEI=false
SKIP_INSTALL=false
JS_DOWNLOAD_LIMIT=200
ARJUN_TIMEOUT=120
THREADS=5
TOOLS_DIR="$HOME/tools"
GO_VERSION="1.22.2"
RATE_LIMIT_DELAY=5          # seconds to wait between API-heavy tools
JS_PARALLEL_DOWNLOADS=10    # concurrent JS file downloads
FRESH_RUN=false             # if true, ignore checkpoint and restart
NO_SUBS=false               # if true, skip subdomain enumeration (list mode)

# ─── v3 FEATURE FLAGS ──────────────────────────────────────
ENABLE_PORTS=false          # port scanning (masscan + nmap)
ENABLE_FUZZ=false           # directory/content fuzzing (ffuf)
ENABLE_DEEP_JS=true         # source maps + jsluice deep JS analysis
ENABLE_TAKEOVER=true        # subdomain takeover detection (subzy)
ENABLE_CORS=true            # CORS misconfiguration scanning
ENABLE_CLOUD=false          # cloud bucket enumeration
ENABLE_GITHUB=false         # GitHub dorking / secret scanning
ENABLE_SCREENSHOTS=true     # screenshot capture (gowitness)
ENABLE_STEALTH=false        # passive-only mode (no active scanning)
FUZZ_WORDLIST=""            # custom wordlist for ffuf (auto-detected if empty)
GITHUB_TOKEN="${GITHUB_TOKEN:-}"  # GitHub token for trufflehog

# ─── COLORS ─────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# ─── GLOBALS ────────────────────────────────────────────────
MODE=""
DOMAIN=""
TARGET_FILE=""
OUTPUT_DIR="./recon-output"
LOG_DIR=""
CURRENT_STAGE=0
TOTAL_STAGES=19
FAILED_STAGES=()
CHECKPOINT_FILE=""
SCRIPT_START=""

# ─── BANNER ─────────────────────────────────────────────────
banner() {
    echo -e "${MAGENTA}${BOLD}"
    cat << 'EOF'
    ____                          __  
   / __ \___  _________  ____   / /_ 
  / /_/ / _ \/ ___/ __ \/ __ \ / __ \
 / _, _/  __/ /__/ /_/ / / / // / / /
/_/ |_|\___/\___/\____/_/ /_(_)_/ /_/ v3.0
                                       
   Elite Bug Bounty Recon Automation
       ⚡ OrsuRecon Framework ⚡
EOF
    echo -e "${NC}"
    echo -e "${CYAN}[*] $(date '+%d-%m-%Y %H:%M:%S') — Starting recon engine${NC}"
    echo ""
}

# ─── LOGGING FUNCTIONS ──────────────────────────────────────
log_info() {
    echo -e "${CYAN}[*] $(date '+%H:%M:%S') $1${NC}"
    echo "[INFO] $(date '+%d-%m-%Y %H:%M:%S') $1" >> "$LOG_DIR/recon.log" 2>/dev/null
}

log_success() {
    echo -e "${GREEN}[✓] $(date '+%H:%M:%S') $1${NC}"
    echo "[SUCCESS] $(date '+%d-%m-%Y %H:%M:%S') $1" >> "$LOG_DIR/recon.log" 2>/dev/null
}

log_error() {
    echo -e "${RED}[✗] $(date '+%H:%M:%S') $1${NC}"
    echo "[ERROR] $(date '+%d-%m-%Y %H:%M:%S') $1" >> "$LOG_DIR/recon.log" 2>/dev/null
    echo "[ERROR] $(date '+%d-%m-%Y %H:%M:%S') $1" >> "$LOG_DIR/errors.log" 2>/dev/null
}

log_warn() {
    echo -e "${YELLOW}[!] $(date '+%H:%M:%S') $1${NC}"
    echo "[WARN] $(date '+%d-%m-%Y %H:%M:%S') $1" >> "$LOG_DIR/recon.log" 2>/dev/null
}

log_stage() {
    CURRENT_STAGE=$((CURRENT_STAGE + 1))
    echo ""
    echo -e "${MAGENTA}${BOLD}═══════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}${BOLD}  [$CURRENT_STAGE/$TOTAL_STAGES] $1${NC}"
    echo -e "${MAGENTA}${BOLD}═══════════════════════════════════════════════════${NC}"
    echo ""
}

# ─── CHECKPOINT / RESUME ─────────────────────────────────────
save_checkpoint() {
    local stage_name="$1"
    echo "$stage_name" >> "$CHECKPOINT_FILE"
}

check_checkpoint() {
    local stage_name="$1"
    if [[ "$FRESH_RUN" == "true" ]]; then
        return 1   # not completed, run it
    fi
    if [[ -f "$CHECKPOINT_FILE" ]] && grep -qxF "$stage_name" "$CHECKPOINT_FILE" 2>/dev/null; then
        log_info "⏭  Skipping '$stage_name' — already completed (checkpoint)"
        return 0   # completed, skip it
    fi
    return 1       # not completed, run it
}

clear_checkpoint() {
    rm -f "$CHECKPOINT_FILE"
}

# ─── RATE LIMIT HELPER ───────────────────────────────────────
rate_limit_pause() {
    local tool_name="$1"
    if [[ "$RATE_LIMIT_DELAY" -gt 0 ]]; then
        log_info "⏳ Rate-limit pause (${RATE_LIMIT_DELAY}s) before $tool_name..."
        sleep "$RATE_LIMIT_DELAY"
    fi
}

# ─── CLEANUP TRAP ────────────────────────────────────────────
# Recursively find and kill all descendant processes
kill_descendants() {
    local pid="$1"
    local child_pids
    child_pids=$(ps -o pid= --ppid "$pid" 2>/dev/null) || return
    for cpid in $child_pids; do
        kill_descendants "$cpid"
        kill -KILL "$cpid" 2>/dev/null
    done
}

cleanup() {
    # Disable all traps to prevent re-entry
    trap '' INT TERM EXIT
    echo ""
    echo -e "${YELLOW}[!] Interrupted! Killing all child processes...${NC}"
    # Log if log dir is available
    if [[ -n "${LOG_DIR:-}" ]] && [[ -d "${LOG_DIR:-}" ]]; then
        echo "[WARN] $(date '+%d-%m-%Y %H:%M:%S') Interrupted by user (Ctrl+C)" >> "$LOG_DIR/recon.log" 2>/dev/null
    fi
    echo -e "${YELLOW}[!] Partial results saved to: ${OUTPUT_DIR:-./recon-output}${NC}"

    # Step 1: Gracefully terminate all direct children
    pkill -TERM -P $$ 2>/dev/null
    sleep 0.5

    # Step 2: Force-kill all descendants (handles nested timeout→tool chains)
    kill_descendants $$

    # Step 3: Kill entire process group as a final sweep
    kill -- -$$ 2>/dev/null

    echo -e "${YELLOW}[!] Cleanup complete. Exiting.${NC}"
    exit 130
}
trap cleanup INT TERM

# ─── SAFE RUN WRAPPER ───────────────────────────────────────
safe_run() {
    local tool_name="$1"
    shift
    local cmd="$*"
    local start_time
    start_time=$(date +%s)

    log_info "Running: $tool_name"

    # Run in background + wait so Ctrl+C trap can fire immediately
    timeout "$STAGE_TIMEOUT" bash -c "$cmd" >> "$LOG_DIR/recon.log" 2>> "$LOG_DIR/errors.log" &
    local pid=$!
    if wait $pid; then
        local elapsed=$(( $(date +%s) - start_time ))
        log_success "$tool_name completed (${elapsed}s)"
        return 0
    else
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            log_error "$tool_name TIMED OUT after ${STAGE_TIMEOUT}s — skipping"
        else
            log_error "$tool_name FAILED (exit: $exit_code) — continuing"
        fi
        FAILED_STAGES+=("$tool_name")
        return 1
    fi
}

# ─── DISCORD NOTIFICATIONS ──────────────────────────────────
discord_notify() {
    local message="$1"
    [[ -z "$DISCORD_WEBHOOK" ]] && return 0

    local host_name
    host_name=$(hostname 2>/dev/null || echo "unknown")
    local timestamp
    timestamp=$(date '+%d-%m-%Y %H:%M:%S')
    local target="${DOMAIN:-$TARGET_FILE}"

    local payload
    payload=$(cat <<EOFPAYLOAD
{
    "embeds": [{
        "title": "🔍 Recon Alert",
        "color": 3447003,
        "fields": [
            {"name": "Target", "value": "\`${target}\`", "inline": true},
            {"name": "Host", "value": "\`${host_name}\`", "inline": true},
            {"name": "Stage", "value": "${message}", "inline": false},
            {"name": "Time", "value": "${timestamp}", "inline": true}
        ]
    }]
}
EOFPAYLOAD
)

    curl -s -o /dev/null -m 5 -H "Content-Type: application/json" \
        -d "$payload" "$DISCORD_WEBHOOK" 2>> "$LOG_DIR/errors.log" &
}

discord_notify_results() {
    local stage="$1"
    local count="$2"
    discord_notify "✅ ${stage} — **${count}** results found"
}

discord_notify_error() {
    local stage="$1"
    [[ -z "$DISCORD_WEBHOOK" ]] && return 0

    local host_name
    host_name=$(hostname 2>/dev/null || echo "unknown")
    local timestamp
    timestamp=$(date '+%d-%m-%Y %H:%M:%S')
    local target="${DOMAIN:-$TARGET_FILE}"

    local payload
    payload=$(cat <<EOFPAYLOAD
{
    "embeds": [{
        "title": "❌ Recon Stage Failed",
        "color": 15158332,
        "fields": [
            {"name": "Target", "value": "\`${target}\`", "inline": true},
            {"name": "Host", "value": "\`${host_name}\`", "inline": true},
            {"name": "Stage", "value": "${stage}", "inline": false},
            {"name": "Time", "value": "${timestamp}", "inline": true},
            {"name": "Action", "value": "Check logs/errors.log", "inline": false}
        ]
    }]
}
EOFPAYLOAD
)

    curl -s -o /dev/null -m 5 -H "Content-Type: application/json" \
        -d "$payload" "$DISCORD_WEBHOOK" 2>> "$LOG_DIR/errors.log" &
}

discord_notify_summary() {
    [[ -z "$DISCORD_WEBHOOK" ]] && return 0

    local host_name
    host_name=$(hostname 2>/dev/null || echo "unknown")
    local timestamp
    timestamp=$(date '+%d-%m-%Y %H:%M:%S')
    local target="${DOMAIN:-$TARGET_FILE}"
    local duration="$1"
    local subs="$2"
    local live="$3"
    local urls="$4"
    local jsfiles="$5"
    local endpoints="$6"
    local params="$7"
    local failed_str="${8:-None}"

    local payload
    payload=$(cat <<EOFPAYLOAD
{
    "embeds": [{
        "title": "🏁 Recon Complete",
        "color": 3066993,
        "fields": [
            {"name": "Target", "value": "\`${target}\`", "inline": true},
            {"name": "Host", "value": "\`${host_name}\`", "inline": true},
            {"name": "Duration", "value": "${duration}", "inline": true},
            {"name": "Subdomains", "value": "${subs}", "inline": true},
            {"name": "Live Hosts", "value": "${live}", "inline": true},
            {"name": "URLs", "value": "${urls}", "inline": true},
            {"name": "JS Files", "value": "${jsfiles}", "inline": true},
            {"name": "Endpoints", "value": "${endpoints}", "inline": true},
            {"name": "Params", "value": "${params}", "inline": true},
            {"name": "Failed Stages", "value": "${failed_str}", "inline": false}
        ]
    }]
}
EOFPAYLOAD
)

    curl -s -o /dev/null -m 10 -H "Content-Type: application/json" \
        -d "$payload" "$DISCORD_WEBHOOK" 2>> "$LOG_DIR/errors.log"
}

# ─── GO INSTALLATION ────────────────────────────────────────
install_go() {
    if command -v go &>/dev/null; then
        log_success "Go already installed: $(go version 2>/dev/null)"
        return 0
    fi

    log_info "Installing Go ${GO_VERSION}..."

    local arch
    arch=$(dpkg --print-architecture 2>/dev/null)
    if [[ -z "$arch" ]]; then
        case "$(uname -m)" in
            x86_64)  arch="amd64" ;;
            aarch64) arch="arm64" ;;
            *)       arch="amd64" ;;
        esac
    fi

    local tarball="go${GO_VERSION}.linux-${arch}.tar.gz"

    if ! wget -q "https://go.dev/dl/${tarball}" -O "/tmp/${tarball}"; then
        log_error "Failed to download Go — check internet connection"
        return 1
    fi

    if command -v sudo &>/dev/null; then
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "/tmp/${tarball}"
    else
        rm -rf /usr/local/go
        tar -C /usr/local -xzf "/tmp/${tarball}"
    fi
    rm -f "/tmp/${tarball}"

    export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
    export GOPATH="$HOME/go"

    # Persist to all shell config files
    for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if [[ -f "$rc" ]] || [[ "$rc" == "$HOME/.bashrc" ]]; then
            if ! grep -q '/usr/local/go/bin' "$rc" 2>/dev/null; then
                {
                    echo ''
                    echo '# Go environment (added by recon.sh)'
                    echo 'export GOPATH=$HOME/go'
                    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin'
                } >> "$rc"
            fi
        fi
    done

    if command -v go &>/dev/null; then
        log_success "Go installed: $(go version 2>/dev/null)"
        return 0
    else
        log_error "Go installation failed — go binary not found in PATH"
        return 1
    fi
}

# ─── TOOL INSTALLATION ──────────────────────────────────────
install_go_tool() {
    local name="$1"
    local pkg="$2"

    if command -v "$name" &>/dev/null; then
        log_info "✓ $name already installed"
        return 0
    fi

    log_info "Installing $name..."
    if go install -v "$pkg" >> "$LOG_DIR/install.log" 2>&1; then
        if command -v "$name" &>/dev/null; then
            log_success "$name installed successfully"
            return 0
        fi
    fi

    log_error "$name installation failed — check logs/install.log"
    return 1
}

install_pip_tool() {
    local name="$1"
    local pkg="$2"

    if command -v "$name" &>/dev/null; then
        log_info "✓ $name already installed"
        return 0
    fi

    log_info "Installing $name via pip3..."
    # Try pipx first (preferred on modern Kali with PEP 668)
    if command -v pipx &>/dev/null; then
        if pipx install "$pkg" >> "$LOG_DIR/install.log" 2>&1; then
            log_success "$name installed via pipx"
            return 0
        fi
    fi
    # Fallback: pip3 with --break-system-packages
    if pip3 install "$pkg" --break-system-packages >> "$LOG_DIR/install.log" 2>&1; then
        log_success "$name installed via pip3"
        return 0
    fi
    # Fallback: pip3 without flag (older systems)
    if pip3 install "$pkg" >> "$LOG_DIR/install.log" 2>&1; then
        log_success "$name installed via pip3"
        return 0
    fi
    log_error "$name pip installation failed"
    return 1
}

install_git_tool() {
    local name="$1"
    local repo="$2"
    local dest="$TOOLS_DIR/$name"

    if [[ -d "$dest" ]]; then
        log_info "✓ $name already cloned"
        return 0
    fi

    log_info "Cloning $name..."
    mkdir -p "$TOOLS_DIR"
    if git clone --depth 1 "$repo" "$dest" >> "$LOG_DIR/install.log" 2>&1; then
        # Install Python dependencies if requirements.txt exists
        if [[ -f "$dest/requirements.txt" ]]; then
            pip3 install -r "$dest/requirements.txt" --break-system-packages >> "$LOG_DIR/install.log" 2>&1 || \
            pip3 install -r "$dest/requirements.txt" >> "$LOG_DIR/install.log" 2>&1
        fi
        log_success "$name cloned to $dest"
        return 0
    else
        log_error "$name clone failed"
        return 1
    fi
}

install_apt_tool() {
    local name="$1"
    local pkg="${2:-$1}"

    if command -v "$name" &>/dev/null; then
        log_info "✓ $name already installed"
        return 0
    fi

    log_info "Installing $name via apt..."
    if command -v sudo &>/dev/null; then
        sudo apt-get install -y -qq "$pkg" >> "$LOG_DIR/install.log" 2>&1
    else
        apt-get install -y -qq "$pkg" >> "$LOG_DIR/install.log" 2>&1
    fi

    if command -v "$name" &>/dev/null; then
        log_success "$name installed via apt"
        return 0
    else
        log_warn "$name apt install may have failed — check install.log"
        return 1
    fi
}

check_system_deps() {
    log_info "Checking system dependencies..."
    local missing=()

    # Map: command_name -> apt_package_name
    declare -A cmd_to_pkg=(
        [curl]="curl" [wget]="wget" [git]="git"
        [python3]="python3" [pip3]="python3-pip" [jq]="jq"
    )

    for cmd in "${!cmd_to_pkg[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("${cmd_to_pkg[$cmd]}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Missing system packages: ${missing[*]}"
        log_info "Attempting to install via apt..."
        if command -v sudo &>/dev/null; then
            sudo apt-get update -qq >> "$LOG_DIR/install.log" 2>&1
            sudo apt-get install -y -qq "${missing[@]}" >> "$LOG_DIR/install.log" 2>&1
        else
            apt-get update -qq >> "$LOG_DIR/install.log" 2>&1
            apt-get install -y -qq "${missing[@]}" >> "$LOG_DIR/install.log" 2>&1
        fi
    fi

    log_success "System dependencies OK"
}

install_all_tools() {
    log_stage "Dependency Check & Installation"

    check_system_deps

    # Ensure pipx is available (best for Python CLI tools on modern Kali)
    if ! command -v pipx &>/dev/null; then
        log_info "Installing pipx..."
        if command -v sudo &>/dev/null; then
            sudo apt-get install -y -qq pipx >> "$LOG_DIR/install.log" 2>&1 || true
        else
            apt-get install -y -qq pipx >> "$LOG_DIR/install.log" 2>&1 || true
        fi
        # Ensure pipx PATH
        pipx ensurepath >> "$LOG_DIR/install.log" 2>&1 || true
        export PATH="$PATH:$HOME/.local/bin"
    fi

    # Go
    install_go || {
        log_error "Go installation failed — Go-based tools will be unavailable"
        discord_notify_error "Go Installation"
        return 1
    }

    # Ensure PATH includes go/bin for this session
    export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

    # ─── Core Go tools (v2 originals) ───
    install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
    install_go_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool "gau"         "github.com/lc/gau/v2/cmd/gau@latest"
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
    install_go_tool "katana"      "github.com/projectdiscovery/katana/cmd/katana@latest"
    install_go_tool "hakrawler"   "github.com/hakluke/hakrawler@latest"
    install_go_tool "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    install_go_tool "gf"          "github.com/tomnomnom/gf@latest"
    install_go_tool "anew"        "github.com/tomnomnom/anew@latest"
    install_go_tool "qsreplace"   "github.com/tomnomnom/qsreplace@latest"
    install_go_tool "unfurl"      "github.com/tomnomnom/unfurl@latest"

    # ─── v3 Go tools ───
    install_go_tool "dnsx"          "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    install_go_tool "alterx"        "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    install_go_tool "puredns"       "github.com/d3mondev/puredns/v2@latest"
    install_go_tool "ffuf"          "github.com/ffuf/ffuf/v2@latest"
    install_go_tool "subzy"         "github.com/PentestPad/subzy@latest"
    install_go_tool "gowitness"     "github.com/sensepost/gowitness@latest"
    install_go_tool "jsluice"       "github.com/BishopFox/jsluice/cmd/jsluice@latest"
    install_go_tool "interactsh-client" "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    install_go_tool "trufflehog"    "github.com/trufflesecurity/trufflehog@latest"

    # ─── System tools via apt (v3) ───
    install_apt_tool "masscan"   "masscan"
    install_apt_tool "nmap"      "nmap"
    install_apt_tool "whatweb"   "whatweb"
    install_apt_tool "wafw00f"   "wafw00f"

    # ─── Python tools ───
    # ParamSpider must be git-cloned (not on PyPI)
    if ! command -v paramspider &>/dev/null; then
        log_info "Installing ParamSpider via git clone..."
        local ps_dir="$TOOLS_DIR/ParamSpider"
        if [[ ! -d "$ps_dir" ]]; then
            mkdir -p "$TOOLS_DIR"
            git clone --depth 1 "https://github.com/devanshbatham/ParamSpider.git" "$ps_dir" >> "$LOG_DIR/install.log" 2>&1
        fi
        if [[ -d "$ps_dir" ]]; then
            # Try pipx first
            if command -v pipx &>/dev/null; then
                pipx install "$ps_dir" >> "$LOG_DIR/install.log" 2>&1 || true
            fi
            # Fallback to pip3 (use absolute path for logs since we cd)
            if ! command -v paramspider &>/dev/null; then
                (cd "$ps_dir" && pip3 install . --break-system-packages >> "$LOG_DIR/install.log" 2>&1) || \
                (cd "$ps_dir" && pip3 install . >> "$LOG_DIR/install.log" 2>&1) || true
            fi
            export PATH="$PATH:$HOME/.local/bin"
            if command -v paramspider &>/dev/null; then
                log_success "ParamSpider installed"
            else
                log_warn "ParamSpider install may have issues — will try direct python3 call"
            fi
        else
            log_error "ParamSpider clone failed"
        fi
    else
        log_info "✓ paramspider already installed"
    fi

    # Arjun — try pipx first, then pip3
    install_pip_tool "arjun" "arjun"

    # Git-cloned tools (v2 originals)
    install_git_tool "LinkFinder"   "https://github.com/GerbenJavado/LinkFinder.git"
    install_git_tool "SecretFinder" "https://github.com/m4ll0k/SecretFinder.git"

    # v3 Git-cloned tools
    install_git_tool "Corsy"        "https://github.com/s0md3v/Corsy.git"
    install_git_tool "cloud_enum"   "https://github.com/initstring/cloud_enum.git"

    # Install jsbeautifier — required by both LinkFinder and SecretFinder
    if ! python3 -c 'import jsbeautifier' 2>/dev/null; then
        log_info "Installing jsbeautifier (required by LinkFinder/SecretFinder)..."
        pip3 install jsbeautifier --break-system-packages >> "$LOG_DIR/install.log" 2>&1 || \
        pip3 install jsbeautifier >> "$LOG_DIR/install.log" 2>&1 || \
        { command -v pipx &>/dev/null && pipx inject linkfinder jsbeautifier >> "$LOG_DIR/install.log" 2>&1; } || \
        log_warn "jsbeautifier install failed — LinkFinder/SecretFinder may not work"
    else
        log_info "✓ jsbeautifier already installed"
    fi

    # gf patterns
    if [[ ! -d "$HOME/.gf" ]] || [[ -z "$(ls -A "$HOME/.gf" 2>/dev/null)" ]]; then
        log_info "Installing gf patterns..."
        mkdir -p "$HOME/.gf"
        local gf_tmp="/tmp/gf-patterns-$$"
        if git clone --depth 1 "https://github.com/tomnomnom/gf.git" "$gf_tmp" >> "$LOG_DIR/install.log" 2>&1; then
            cp "$gf_tmp/examples/"*.json "$HOME/.gf/" 2>/dev/null
            rm -rf "$gf_tmp"
            log_success "gf patterns installed"
        else
            log_warn "gf patterns clone failed — gf stage may produce no results"
        fi
    else
        log_info "✓ gf patterns already installed"
    fi

    # Create default gau config to suppress "config not found" warning
    if [[ ! -f "$HOME/.gau.toml" ]]; then
        log_info "Creating default gau config..."
        cat > "$HOME/.gau.toml" <<'EOFGAU'
# gau configuration — created by recon.sh
threads = 5
verbose = false
retries = 3
subdomains = false
providers = ["wayback", "commoncrawl", "otx", "urlscan"]
blacklist = ["ttf", "woff", "svg", "png", "jpg", "jpeg", "gif", "ico", "css"]
EOFGAU
        log_success "gau config created at ~/.gau.toml"
    fi

    # Download resolvers list for puredns if not present
    local resolvers_file="$TOOLS_DIR/resolvers.txt"
    if [[ ! -f "$resolvers_file" ]]; then
        log_info "Downloading public DNS resolvers list for puredns..."
        mkdir -p "$TOOLS_DIR"
        curl -sL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt" \
            -o "$resolvers_file" 2>> "$LOG_DIR/errors.log" || \
        # Fallback: create a minimal resolvers list
        printf '8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9\n' > "$resolvers_file"
        log_success "Resolvers list saved to $resolvers_file"
    fi

    # Download SecLists common wordlist for ffuf if not present
    local wordlists_dir="$TOOLS_DIR/wordlists"
    if [[ ! -f "$wordlists_dir/common.txt" ]]; then
        log_info "Downloading common wordlist for fuzzing..."
        mkdir -p "$wordlists_dir"
        curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
            -o "$wordlists_dir/common.txt" 2>> "$LOG_DIR/errors.log" || true
        curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api-endpoints.txt" \
            -o "$wordlists_dir/api-endpoints.txt" 2>> "$LOG_DIR/errors.log" || true
        log_success "Wordlists downloaded to $wordlists_dir"
    fi

    log_success "Tool installation complete"
}

# ─── PRE-FLIGHT TOOL VERIFICATION ─────────────────────────────
verify_tools() {
    log_info "Verifying all tools are available in PATH..."

    # Ensure PATH is fully set
    export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin"

    # Define required tools and their install methods
    # Format: "command|install_type|install_target"
    local tools=(
        "subfinder|go|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "assetfinder|go|github.com/tomnomnom/assetfinder@latest"
        "httpx|go|github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "gau|go|github.com/lc/gau/v2/cmd/gau@latest"
        "waybackurls|go|github.com/tomnomnom/waybackurls@latest"
        "katana|go|github.com/projectdiscovery/katana/cmd/katana@latest"
        "hakrawler|go|github.com/hakluke/hakrawler@latest"
        "nuclei|go|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "gf|go|github.com/tomnomnom/gf@latest"
        "anew|go|github.com/tomnomnom/anew@latest"
        "qsreplace|go|github.com/tomnomnom/qsreplace@latest"
        "unfurl|go|github.com/tomnomnom/unfurl@latest"
        "arjun|pip|arjun"
        "dnsx|go|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "alterx|go|github.com/projectdiscovery/alterx/cmd/alterx@latest"
        "puredns|go|github.com/d3mondev/puredns/v2@latest"
        "ffuf|go|github.com/ffuf/ffuf/v2@latest"
        "subzy|go|github.com/PentestPad/subzy@latest"
        "gowitness|go|github.com/sensepost/gowitness@latest"
        "jsluice|go|github.com/BishopFox/jsluice/cmd/jsluice@latest"
        "interactsh-client|go|github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        "trufflehog|go|github.com/trufflesecurity/trufflehog@latest"
    )

    local missing=0
    local installed=0

    for entry in "${tools[@]}"; do
        IFS='|' read -r cmd install_type install_target <<< "$entry"
        if command -v "$cmd" &>/dev/null; then
            continue
        fi

        log_warn "$cmd not found in PATH — attempting auto-install..."
        missing=$((missing + 1))

        case "$install_type" in
            go)
                if command -v go &>/dev/null; then
                    go install -v "$install_target" >> "$LOG_DIR/install.log" 2>&1 && \
                        log_success "$cmd installed" && installed=$((installed + 1)) || \
                        log_error "$cmd auto-install failed"
                else
                    log_error "$cmd requires Go but Go is not installed"
                fi
                ;;
            pip)
                install_pip_tool "$cmd" "$install_target" && installed=$((installed + 1)) || \
                    log_error "$cmd auto-install failed"
                ;;
        esac
    done

    # Check git-cloned tools (not in PATH, but need directory + deps)
    for tool_name in "LinkFinder" "SecretFinder" "Corsy" "cloud_enum"; do
        if [[ ! -d "$TOOLS_DIR/$tool_name" ]]; then
            log_warn "$tool_name not found — will be unavailable"
        fi
    done

    # Check paramspider separately (installed via git clone + pip)
    if ! command -v paramspider &>/dev/null; then
        log_warn "paramspider not found — parameter discovery will be limited"
    fi

    # Check apt tools
    for apt_tool in "masscan" "nmap" "whatweb" "wafw00f"; do
        if ! command -v "$apt_tool" &>/dev/null; then
            log_warn "$apt_tool not found — related stage will be skipped"
        fi
    done

    if [[ $missing -eq 0 ]]; then
        log_success "All tools verified and available ✓"
    else
        log_info "Missing: $missing | Auto-installed: $installed | Still missing: $((missing - installed))"
    fi
}

# ════════════════════════════════════════════════════════════
#                     RECON STAGES
# ════════════════════════════════════════════════════════════

# ─── STAGE 1: SUBDOMAIN ENUMERATION ─────────────────────────
stage_subdomains() {
    log_stage "Subdomain Enumeration"

    local subs_dir="$OUTPUT_DIR/subdomains"
    local raw_dir="$subs_dir/.raw_$$"
    mkdir -p "$raw_dir"

    # Build list of domains to enumerate
    local domains=()
    if [[ "$MODE" == "domain" ]]; then
        domains=("$DOMAIN")
    elif [[ "$MODE" == "list" ]] && [[ -f "$TARGET_FILE" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            domains+=("$line")
        done < "$TARGET_FILE"
    fi

    log_info "Enumerating subdomains for ${#domains[@]} domain(s)..."

    for target_domain in "${domains[@]}"; do
        log_info "─── Enumerating: $target_domain ───"
        local safe_name
        safe_name=$(echo "$target_domain" | tr -c 'a-zA-Z0-9.-' '_')

        # subfinder (writes to its own temp file to avoid race conditions)
        if command -v subfinder &>/dev/null; then
            (
                subfinder -d "$target_domain" -all -silent 2>> "$LOG_DIR/errors.log" > "$raw_dir/subfinder_${safe_name}.txt"
            ) &
            local pid_subfinder=$!
        fi

        # assetfinder (writes to its own temp file)
        if command -v assetfinder &>/dev/null; then
            (
                assetfinder --subs-only "$target_domain" 2>> "$LOG_DIR/errors.log" > "$raw_dir/assetfinder_${safe_name}.txt"
            ) &
            local pid_assetfinder=$!
        fi

        # crt.sh (curl-based, writes to its own temp file)
        (
            curl -s -m 60 "https://crt.sh/?q=%25.${target_domain}&output=json" 2>> "$LOG_DIR/errors.log" \
                | jq -r '.[].name_value' 2>/dev/null \
                | sed 's/\*\.//g' \
                | sort -u > "$raw_dir/crtsh_${safe_name}.txt"
        ) &
        local pid_crtsh=$!

        # Wait for all parallel jobs for this domain
        [[ -n "${pid_subfinder:-}" ]] && wait "$pid_subfinder" 2>/dev/null
        [[ -n "${pid_assetfinder:-}" ]] && wait "$pid_assetfinder" 2>/dev/null
        wait "$pid_crtsh" 2>/dev/null

        # Also add the root domain itself
        echo "$target_domain" > "$raw_dir/root_${safe_name}.txt"
    done

    # Merge all per-tool files, dedup, and remove 'www.' noise
    cat "$raw_dir"/*.txt 2>/dev/null | sed 's/^www\.//' | sort -u | grep -v '^$' > "$subs_dir/all.txt"
    rm -rf "$raw_dir"

    local count
    count=$(wc -l < "$subs_dir/all.txt" 2>/dev/null || echo "0")
    log_success "Subdomain enumeration complete: $count unique subdomains across ${#domains[@]} domain(s)"

    discord_notify_results "Subdomain Enumeration" "$count"
    save_checkpoint "stage_subdomains"
}

# ─── STAGE 2: SUBDOMAIN PERMUTATION + DNS RESOLUTION ────────
stage_dns_resolution() {
    log_stage "Subdomain Permutation & DNS Resolution"

    local subs_dir="$OUTPUT_DIR/subdomains"
    local subs_file="$subs_dir/all.txt"
    local resolvers="$TOOLS_DIR/resolvers.txt"

    if [[ ! -s "$subs_file" ]]; then
        log_warn "No subdomains found — skipping permutation"
        save_checkpoint "stage_dns_resolution"
        return 0
    fi

    # Step 1: Generate permutations with alterx
    if command -v alterx &>/dev/null; then
        log_info "Generating subdomain permutations with alterx..."
        local perms_file="$subs_dir/permutations.txt"
        timeout "$STAGE_TIMEOUT" alterx -l "$subs_file" -enrich -silent \
            > "$perms_file" 2>> "$LOG_DIR/errors.log" || true

        local perm_count
        perm_count=$(wc -l < "$perms_file" 2>/dev/null || echo "0")
        log_success "alterx generated $perm_count permutations"

        # Merge permutations with original subs
        if [[ "$perm_count" -gt 0 ]]; then
            cat "$subs_file" "$perms_file" | sort -u > "$subs_dir/all_with_perms.txt"
        else
            cp "$subs_file" "$subs_dir/all_with_perms.txt"
        fi
    else
        log_warn "alterx not available — skipping permutations"
        cp "$subs_file" "$subs_dir/all_with_perms.txt"
    fi

    # Step 2: Resolve with puredns (includes wildcard filtering)
    if command -v puredns &>/dev/null && [[ -f "$resolvers" ]]; then
        log_info "Resolving subdomains with puredns (wildcard filtering enabled)..."
        timeout "$STAGE_TIMEOUT" puredns resolve "$subs_dir/all_with_perms.txt" \
            -r "$resolvers" \
            --rate-limit 500 \
            -w "$subs_dir/resolved.txt" \
            2>> "$LOG_DIR/errors.log" &
        wait $! || {
            log_warn "puredns timed out or failed"
            FAILED_STAGES+=("puredns")
        }

        if [[ -s "$subs_dir/resolved.txt" ]]; then
            local resolved_count
            resolved_count=$(wc -l < "$subs_dir/resolved.txt" 2>/dev/null || echo "0")
            log_success "puredns resolved $resolved_count subdomains (wildcards filtered)"
            # Update all.txt with resolved-only subs
            cp "$subs_dir/resolved.txt" "$subs_dir/all.txt"
        fi
    else
        log_warn "puredns or resolvers not available — skipping DNS resolution"
    fi

    # Step 3: Extract CNAME and A records with dnsx
    if command -v dnsx &>/dev/null; then
        log_info "Extracting DNS records with dnsx..."
        # Get A records (IPs)
        timeout "$STAGE_TIMEOUT" dnsx -l "$subs_dir/all.txt" -a -resp-only -silent \
            > "$subs_dir/ips.txt" 2>> "$LOG_DIR/errors.log" || true
        # Get CNAME records (for takeover detection later)
        timeout "$STAGE_TIMEOUT" dnsx -l "$subs_dir/all.txt" -cname -resp -silent \
            > "$subs_dir/cnames.txt" 2>> "$LOG_DIR/errors.log" || true

        local ip_count cname_count
        ip_count=$(wc -l < "$subs_dir/ips.txt" 2>/dev/null || echo "0")
        cname_count=$(wc -l < "$subs_dir/cnames.txt" 2>/dev/null || echo "0")
        log_success "dnsx: $ip_count IPs, $cname_count CNAMEs extracted"
    else
        log_warn "dnsx not available — skipping DNS record extraction"
    fi

    # Cleanup temp
    rm -f "$subs_dir/all_with_perms.txt" "$subs_dir/permutations.txt"

    discord_notify_results "DNS Resolution" "$(wc -l < "$subs_dir/all.txt" 2>/dev/null || echo "0") resolved"
    save_checkpoint "stage_dns_resolution"
}

# ─── STAGE 3: LIVE HOST PROBING ─────────────────────────────
stage_livehost() {
    log_stage "Live Host Probing"

    local subs_file="$OUTPUT_DIR/subdomains/all.txt"
    local subs_dir="$OUTPUT_DIR/subdomains"

    if [[ ! -s "$subs_file" ]]; then
        log_error "No subdomains found — skipping live host probing"
        discord_notify_error "Live Host Probing (no input)"
        touch "$subs_dir/live_hosts.txt"
        save_checkpoint "stage_livehost"
        return 1
    fi

    if ! command -v httpx &>/dev/null; then
        log_error "httpx not available — skipping"
        touch "$subs_dir/live_hosts.txt"
        save_checkpoint "stage_livehost"
        return 1
    fi

    log_info "Running httpx probing..."
    timeout "$STAGE_TIMEOUT" bash -c "cat '$subs_file' | httpx -silent -sc -title -td -cl -fr -t $THREADS -o '$subs_dir/live_details.csv'" \
        >> "$LOG_DIR/recon.log" 2>> "$LOG_DIR/errors.log" &
    wait $! || {
        log_warn "httpx timed out or failed"
        FAILED_STAGES+=("httpx")
    }

    # Extract clean host list (just URLs)
    if [[ -f "$subs_dir/live_details.csv" ]]; then
        awk '{print $1}' "$subs_dir/live_details.csv" | sort -u > "$subs_dir/live_hosts.txt"

        local count
        count=$(wc -l < "$subs_dir/live_hosts.txt" 2>/dev/null || echo "0")
        log_success "Live hosts: $count responding"
    else
        touch "$subs_dir/live_hosts.txt"
        log_warn "httpx produced no output"
    fi
    save_checkpoint "stage_livehost"
}

# ─── STAGE 4: PORT SCANNING ─────────────────────────────────
stage_ports() {
    log_stage "Port Scanning"

    if [[ "$ENABLE_PORTS" != "true" ]]; then
        log_info "Port scanning disabled — use --ports flag to enable"
        save_checkpoint "stage_ports"
        return 0
    fi

    if [[ "$ENABLE_STEALTH" == "true" ]]; then
        log_info "Stealth mode — skipping port scanning"
        save_checkpoint "stage_ports"
        return 0
    fi

    local ips_file="$OUTPUT_DIR/subdomains/ips.txt"
    local ports_dir="$OUTPUT_DIR/ports"
    mkdir -p "$ports_dir"

    # Fall back to extracting IPs from live hosts if dnsx didn't run
    if [[ ! -s "$ips_file" ]]; then
        local live_hosts="$OUTPUT_DIR/subdomains/live_hosts.txt"
        if [[ -s "$live_hosts" ]]; then
            log_info "Extracting IPs from live hosts..."
            sed -E 's|^https?://||; s|/.*||; s|:.*||' "$live_hosts" | sort -u > "$ips_file"
        else
            log_warn "No IPs available — skipping port scanning"
            save_checkpoint "stage_ports"
            return 1
        fi
    fi

    # Step 1: masscan — fast top-ports sweep
    if command -v masscan &>/dev/null; then
        log_info "Running masscan (top 1000 ports)..."
        # masscan needs root/sudo for raw sockets
        local masscan_cmd="masscan -iL '$ips_file' --top-ports 1000 --rate 1000 -oG '$ports_dir/masscan_raw.txt'"
        if [[ $EUID -ne 0 ]] && command -v sudo &>/dev/null; then
            masscan_cmd="sudo $masscan_cmd"
        fi
        timeout "$STAGE_TIMEOUT" bash -c "$masscan_cmd" \
            >> "$LOG_DIR/recon.log" 2>> "$LOG_DIR/errors.log" &
        wait $! || {
            log_warn "masscan timed out or failed (may need root/sudo)"
            FAILED_STAGES+=("masscan")
        }

        # Parse masscan grepable output → ip:port format
        if [[ -f "$ports_dir/masscan_raw.txt" ]]; then
            grep '^Host:' "$ports_dir/masscan_raw.txt" 2>/dev/null \
                | awk '{print $2":"$5}' | sed 's|/.*||' | sort -u > "$ports_dir/open_ports.txt"
            local port_count
            port_count=$(wc -l < "$ports_dir/open_ports.txt" 2>/dev/null || echo "0")
            log_success "masscan found $port_count open port(s)"

            # Filter non-standard ports (not 80/443)
            grep -v -E ':(80|443)$' "$ports_dir/open_ports.txt" > "$ports_dir/interesting_ports.txt" 2>/dev/null || true
        fi
    else
        log_warn "masscan not available — skipping fast port scan"
    fi

    # Step 2: nmap — detailed service detection on open ports
    if command -v nmap &>/dev/null && [[ -s "${ports_dir}/open_ports.txt" ]]; then
        log_info "Running nmap service detection on open ports..."
        # Extract unique IPs that had open ports
        cut -d: -f1 "$ports_dir/open_ports.txt" | sort -u > "$ports_dir/nmap_targets.txt"
        # Extract ports list
        local ports_list
        ports_list=$(cut -d: -f2 "$ports_dir/open_ports.txt" | sort -un | paste -sd, -)

        # Guard: only run nmap if ports_list is non-empty
        if [[ -n "$ports_list" ]]; then
            timeout "$STAGE_TIMEOUT" nmap -iL "$ports_dir/nmap_targets.txt" \
                -p "$ports_list" -sV -sC --open \
                -oN "$ports_dir/nmap_results.txt" \
                -oX "$ports_dir/nmap_results.xml" \
                >> "$LOG_DIR/recon.log" 2>> "$LOG_DIR/errors.log" &
            wait $! || {
                log_warn "nmap timed out or failed"
                FAILED_STAGES+=("nmap")
            }
            log_success "nmap service detection complete"
        else
            log_warn "No valid ports extracted — skipping nmap"
        fi
    else
        log_info "Skipping nmap — no open ports or nmap not available"
    fi

    discord_notify_results "Port Scanning" "$(wc -l < "${ports_dir}/open_ports.txt" 2>/dev/null || echo "0") ports"
    save_checkpoint "stage_ports"
}

# ─── STAGE 5: TECH FINGERPRINTING + WAF DETECTION ───────────
stage_tech_detect() {
    log_stage "Technology Fingerprinting & WAF Detection"

    local live_hosts="$OUTPUT_DIR/subdomains/live_hosts.txt"
    local tech_dir="$OUTPUT_DIR/tech"
    mkdir -p "$tech_dir"

    if [[ ! -s "$live_hosts" ]]; then
        log_warn "No live hosts — skipping tech detection"
        save_checkpoint "stage_tech_detect"
        return 1
    fi

    # whatweb — deep tech fingerprinting
    if command -v whatweb &>/dev/null; then
        log_info "Running whatweb for technology fingerprinting..."
        local ww_count=0
        while IFS= read -r host; do
            [[ -z "$host" ]] && continue
            ww_count=$((ww_count + 1))
            [[ $ww_count -gt 50 ]] && { log_info "whatweb: capped at 50 hosts"; break; }
            timeout 30 whatweb -q --log-json="$tech_dir/whatweb_raw.jsonl" "$host" \
                2>> "$LOG_DIR/errors.log" || true
        done < "$live_hosts"
        log_success "whatweb scanned $ww_count hosts"

        # Parse whatweb results into a clean summary
        if [[ -f "$tech_dir/whatweb_raw.jsonl" ]]; then
            jq -r 'select(.target) | "\(.target) | \(.plugins | keys | join(", "))"' \
                "$tech_dir/whatweb_raw.jsonl" > "$tech_dir/fingerprints.txt" 2>/dev/null || true
        fi
    else
        log_warn "whatweb not available — skipping tech fingerprinting"
    fi

    # wafw00f — WAF detection
    if command -v wafw00f &>/dev/null; then
        log_info "Running wafw00f for WAF detection..."
        timeout "$STAGE_TIMEOUT" wafw00f -i "$live_hosts" -o "$tech_dir/waf_results.txt" \
            >> "$LOG_DIR/recon.log" 2>> "$LOG_DIR/errors.log" &
        wait $! || {
            log_warn "wafw00f timed out or failed"
            FAILED_STAGES+=("wafw00f")
        }

        if [[ -f "$tech_dir/waf_results.txt" ]]; then
            local waf_count
            waf_count=$(grep -ci 'is behind' "$tech_dir/waf_results.txt" 2>/dev/null || echo "0")
            log_success "WAF detected on $waf_count host(s)"
        fi
    else
        log_warn "wafw00f not available — skipping WAF detection"
    fi

    discord_notify_results "Tech Fingerprinting" "$(wc -l < "$tech_dir/fingerprints.txt" 2>/dev/null || echo "0") hosts profiled"
    save_checkpoint "stage_tech_detect"
}

# ─── STAGE 6: SCREENSHOTS ───────────────────────────────────
stage_screenshots() {
    log_stage "Screenshot Capture"

    if [[ "$ENABLE_SCREENSHOTS" != "true" ]]; then
        log_info "Screenshots disabled — use --screenshots flag to enable"
        save_checkpoint "stage_screenshots"
        return 0
    fi

    local live_hosts="$OUTPUT_DIR/subdomains/live_hosts.txt"
    local screenshots_dir="$OUTPUT_DIR/screenshots"
    mkdir -p "$screenshots_dir"

    if [[ ! -s "$live_hosts" ]]; then
        log_warn "No live hosts — skipping screenshots"
        save_checkpoint "stage_screenshots"
        return 1
    fi

    if command -v gowitness &>/dev/null; then
        log_info "Running gowitness screenshot capture..."
        timeout "$STAGE_TIMEOUT" gowitness scan file -f "$live_hosts" \
            --screenshot-path "$screenshots_dir" \
            --no-color \
            >> "$LOG_DIR/recon.log" 2>> "$LOG_DIR/errors.log" &
        wait $! || {
            log_warn "gowitness timed out or failed"
            FAILED_STAGES+=("gowitness")
        }
        local ss_count
        ss_count=$(find "$screenshots_dir" -name '*.png' -o -name '*.jpeg' -o -name '*.jpg' 2>/dev/null | wc -l)
        log_success "Captured $ss_count screenshots"
    else
        log_warn "gowitness not available — skipping screenshots"
    fi

    save_checkpoint "stage_screenshots"
}

# ─── STAGE 7: URL COLLECTION ────────────────────────────────
stage_urls() {
    log_stage "URL & Endpoint Collection"

    local live_hosts="$OUTPUT_DIR/subdomains/live_hosts.txt"
    local urls_dir="$OUTPUT_DIR/urls"
    local raw_file="$urls_dir/raw_urls.txt"
    touch "$raw_file"

    if [[ ! -s "$live_hosts" ]]; then
        log_warn "No live hosts — skipping URL collection"
        touch "$urls_dir/all_urls.txt" "$urls_dir/inscope_urls.txt"
        save_checkpoint "stage_urls"
        return 1
    fi

    # Create a clean domain-only list (gau/waybackurls need bare domains, not full URLs)
    local domains_file="$urls_dir/domains_only.txt"
    sed -E 's|^https?://||; s|/.*||; s|:.*||' "$live_hosts" | sort -u > "$domains_file"
    log_info "Extracted $(wc -l < "$domains_file") unique domains from live hosts"

    # gau — historical URLs (needs bare domains)
    if command -v gau &>/dev/null; then
        log_info "Running gau..."
        timeout "$STAGE_TIMEOUT" bash -c "cat '$domains_file' | gau --threads $THREADS --verbose" \
            >> "$raw_file" 2>> "$LOG_DIR/errors.log" &
        wait $! || {
            log_warn "gau timed out or failed"
            FAILED_STAGES+=("gau")
        }
        local gau_count=$(wc -l < "$raw_file" 2>/dev/null || echo "0")
        log_success "gau found $gau_count URLs"
        rate_limit_pause "waybackurls"
    fi

    # waybackurls (needs bare domains)
    if command -v waybackurls &>/dev/null; then
        log_info "Running waybackurls..."
        timeout "$STAGE_TIMEOUT" bash -c "cat '$domains_file' | waybackurls" \
            >> "$raw_file" 2>> "$LOG_DIR/errors.log" &
        wait $! || {
            log_warn "waybackurls timed out or failed"
            FAILED_STAGES+=("waybackurls")
        }
        log_success "waybackurls completed (total URLs so far: $(wc -l < "$raw_file" 2>/dev/null || echo "0"))"
        rate_limit_pause "Wayback CDX / katana"
    fi

    # Fallback: Direct Wayback CDX API via curl (if gau/waybackurls returned nothing)
    local url_count_so_far
    url_count_so_far=$(wc -l < "$raw_file" 2>/dev/null || echo "0")
    if [[ "$url_count_so_far" -eq 0 ]]; then
        log_warn "gau/waybackurls returned 0 URLs — using direct Wayback CDX API fallback..."
        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            log_info "Fetching Wayback URLs for: $domain"
            curl -s -m 120 "https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey" \
                2>> "$LOG_DIR/errors.log" >> "$raw_file" || true
        done < "$domains_file"
        local fallback_count
        fallback_count=$(wc -l < "$raw_file" 2>/dev/null || echo "0")
        log_success "Wayback CDX fallback found $fallback_count URLs"
    fi

    # katana — active crawling (skip in stealth mode)
    if [[ "$ENABLE_STEALTH" != "true" ]] && command -v katana &>/dev/null; then
        rate_limit_pause "katana"
        local katana_out="$urls_dir/katana_out.txt"
        log_info "Running katana (timeout: 600s)..."
        timeout 600 katana -list "$live_hosts" -d 3 -silent -rl 10 -o "$katana_out" \
            >> "$LOG_DIR/recon.log" 2>> "$LOG_DIR/errors.log" &
        wait $! || {
            log_warn "katana timed out or failed — continuing"
            FAILED_STAGES+=("katana")
        }
        [[ -f "$katana_out" ]] && cat "$katana_out" >> "$raw_file"
    fi

    # hakrawler (skip in stealth mode)
    if [[ "$ENABLE_STEALTH" != "true" ]] && command -v hakrawler &>/dev/null; then
        rate_limit_pause "hakrawler"
        log_info "Running hakrawler..."
        timeout "$STAGE_TIMEOUT" bash -c "cat '$live_hosts' | hakrawler -d 3 -subs" \
            >> "$raw_file" 2>> "$LOG_DIR/errors.log" &
        wait $! || {
            log_warn "hakrawler timed out or failed"
            FAILED_STAGES+=("hakrawler")
        }
        log_success "hakrawler completed"
    fi

    # Dedup
    sort -u "$raw_file" | grep -v '^$' > "$urls_dir/all_urls.txt"
    rm -f "$raw_file"

    # Scope filter — build pattern from domain or all domains in list
    if [[ "$MODE" == "domain" ]]; then
        local scope_pattern
        scope_pattern=$(echo "$DOMAIN" | sed 's/\./\\./g')
        grep -iE "$scope_pattern" "$urls_dir/all_urls.txt" > "$urls_dir/inscope_urls.txt" 2>/dev/null
    elif [[ "$MODE" == "list" ]] && [[ -f "$TARGET_FILE" ]]; then
        # Build scope pattern from all domains in target file
        local scope_pattern
        scope_pattern=$(sed '/^$/d; s/\./\\./g' "$TARGET_FILE" | paste -sd'|' -)
        if [[ -n "$scope_pattern" ]]; then
            grep -iE "$scope_pattern" "$urls_dir/all_urls.txt" > "$urls_dir/inscope_urls.txt" 2>/dev/null
            local all_count inscope_count
            all_count=$(wc -l < "$urls_dir/all_urls.txt" 2>/dev/null || echo "0")
            inscope_count=$(wc -l < "$urls_dir/inscope_urls.txt" 2>/dev/null || echo "0")
            log_info "Scope filter: $all_count total → $inscope_count in-scope"
        else
            cp "$urls_dir/all_urls.txt" "$urls_dir/inscope_urls.txt"
        fi
    else
        cp "$urls_dir/all_urls.txt" "$urls_dir/inscope_urls.txt"
    fi

    local count
    count=$(wc -l < "$urls_dir/inscope_urls.txt" 2>/dev/null || echo "0")
    log_success "URL collection complete: $count in-scope URLs"

    discord_notify_results "URL Collection" "$count"
    save_checkpoint "stage_urls"
}

# ─── STAGE 8: CONTENT/DIRECTORY FUZZING ─────────────────────
stage_fuzzing() {
    log_stage "Content & Directory Fuzzing"

    if [[ "$ENABLE_FUZZ" != "true" ]]; then
        log_info "Fuzzing disabled — use --fuzz flag to enable"
        save_checkpoint "stage_fuzzing"
        return 0
    fi

    if [[ "$ENABLE_STEALTH" == "true" ]]; then
        log_info "Stealth mode — skipping fuzzing"
        save_checkpoint "stage_fuzzing"
        return 0
    fi

    local live_hosts="$OUTPUT_DIR/subdomains/live_hosts.txt"
    local fuzz_dir="$OUTPUT_DIR/fuzzing"
    mkdir -p "$fuzz_dir"

    if [[ ! -s "$live_hosts" ]]; then
        log_warn "No live hosts — skipping fuzzing"
        save_checkpoint "stage_fuzzing"
        return 1
    fi

    if ! command -v ffuf &>/dev/null; then
        log_error "ffuf not available — skipping fuzzing"
        save_checkpoint "stage_fuzzing"
        return 1
    fi

    # Determine wordlist
    local wordlist="${FUZZ_WORDLIST:-}"
    if [[ -z "$wordlist" ]] || [[ ! -f "$wordlist" ]]; then
        # Auto-detect wordlist locations
        for wl in "$TOOLS_DIR/wordlists/common.txt" \
                  "/usr/share/seclists/Discovery/Web-Content/common.txt" \
                  "/usr/share/wordlists/dirb/common.txt" \
                  "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"; do
            if [[ -f "$wl" ]]; then
                wordlist="$wl"
                break
            fi
        done
    fi

    if [[ -z "$wordlist" ]] || [[ ! -f "$wordlist" ]]; then
        log_error "No wordlist found — install SecLists or use --wordlist flag"
        save_checkpoint "stage_fuzzing"
        return 1
    fi

    log_info "Using wordlist: $wordlist"
    log_info "Fuzzing top live hosts (max 20)..."

    local fuzz_count=0
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        fuzz_count=$((fuzz_count + 1))
        [[ $fuzz_count -gt 20 ]] && break

        local safe_host
        safe_host=$(echo "$host" | sed 's|https\?://||; s|/||g; s|:|-|g')
        log_info "ffuf [$fuzz_count/20]: $host"

        timeout 120 ffuf -u "${host}/FUZZ" \
            -w "$wordlist" \
            -mc 200,301,302,307,401,403,405,500 \
            -fc 404 \
            -ac \
            -sf \
            -se \
            -t "$THREADS" \
            -rate 50 \
            -maxtime-job 90 \
            -s \
            -noninteractive \
            -o "$fuzz_dir/ffuf_${safe_host}.json" \
            -of json \
            >> "$LOG_DIR/recon.log" 2>> "$LOG_DIR/errors.log" || true
    done < "$live_hosts"

    # Merge all ffuf results into a summary
    touch "$fuzz_dir/all_findings.txt"
    for f in "$fuzz_dir"/ffuf_*.json; do
        [[ -f "$f" ]] || continue
        jq -r '.results[]? | "\(.url) [\(.status)] [\(.length)B]"' "$f" \
            >> "$fuzz_dir/all_findings.txt" 2>/dev/null || true
    done
    sort -u -o "$fuzz_dir/all_findings.txt" "$fuzz_dir/all_findings.txt"

    local findings_count
    findings_count=$(wc -l < "$fuzz_dir/all_findings.txt" 2>/dev/null || echo "0")
    log_success "Fuzzing complete: $findings_count unique paths found across $fuzz_count hosts"

    discord_notify_results "Directory Fuzzing" "$findings_count"
    save_checkpoint "stage_fuzzing"
}

# ─── STAGE 9: JAVASCRIPT ANALYSIS (v3 enhanced) ─────────────
stage_js_analysis() {
    log_stage "JavaScript File Extraction & Analysis"

    local urls_file="$OUTPUT_DIR/urls/inscope_urls.txt"
    local js_dir="$OUTPUT_DIR/js"
    mkdir -p "$js_dir/files" "$js_dir/sourcemaps"

    if [[ ! -s "$urls_file" ]]; then
        log_warn "No in-scope URLs — skipping JS analysis"
        save_checkpoint "stage_js_analysis"
        return 1
    fi

    # Extract JS URLs
    grep -iE '\.(js|mjs)(\?|$)' "$urls_file" 2>/dev/null | sort -u > "$js_dir/js_urls.txt"

    local js_count
    js_count=$(wc -l < "$js_dir/js_urls.txt" 2>/dev/null || echo "0")
    log_info "Found $js_count JS file URLs"

    if [[ "$js_count" -eq 0 ]]; then
        log_warn "No JS files found"
        touch "$js_dir/linkfinder_results.txt" "$js_dir/secrets_found.txt" "$js_dir/grep_extracts.txt"
        save_checkpoint "stage_js_analysis"
        return 0
    fi

    # Download JS files (limited) — parallel via xargs
    log_info "Downloading JS files (max $JS_DOWNLOAD_LIMIT, ${JS_PARALLEL_DOWNLOADS} parallel)..."
    head -n "$JS_DOWNLOAD_LIMIT" "$js_dir/js_urls.txt" | \
        xargs -I{} -P "$JS_PARALLEL_DOWNLOADS" bash -c '
            url="$1"
            js_dir="$2"
            filename=$(echo "$url" | md5sum | cut -d" " -f1).js
            if curl -s -L -m 10 "$url" -o "$js_dir/files/$filename" 2>/dev/null; then
                echo "$url -> $filename" >> "$js_dir/url_map.txt"
            fi
        ' _ {} "$js_dir"
    local dl_count
    dl_count=$(find "$js_dir/files" -name '*.js' -size +0c 2>/dev/null | wc -l)
    log_success "Downloaded $dl_count JS files (parallel)"

    # ─── v3: Source map extraction ───
    if [[ "$ENABLE_DEEP_JS" == "true" ]]; then
        log_info "Checking for JavaScript source maps (.js.map)..."
        touch "$js_dir/sourcemap_urls.txt"
        # Use process substitution instead of pipe to avoid subshell variable scope loss
        while IFS= read -r js_url; do
            local map_url="${js_url}.map"
            local map_file
            map_file=$(echo "$js_url" | md5sum | cut -d" " -f1).js.map
            if curl -s -L -m 5 -o "$js_dir/sourcemaps/$map_file" -w "%{http_code}" "$map_url" 2>/dev/null | grep -q '^200$'; then
                # Verify it's actually a source map (contains "mappings" key)
                if head -c 500 "$js_dir/sourcemaps/$map_file" | grep -q '"mappings"' 2>/dev/null; then
                    echo "$map_url -> $map_file" >> "$js_dir/sourcemap_urls.txt"
                else
                    rm -f "$js_dir/sourcemaps/$map_file"
                fi
            else
                rm -f "$js_dir/sourcemaps/$map_file"
            fi
        done < <(head -n 100 "$js_dir/js_urls.txt")
        local sourcemap_total
        sourcemap_total=$(wc -l < "$js_dir/sourcemap_urls.txt" 2>/dev/null || echo "0")
        if [[ "$sourcemap_total" -gt 0 ]]; then
            log_success "🔥 Found $sourcemap_total source maps! (full source code exposed)"
            discord_notify "🔥 **$sourcemap_total source maps found** — full original source code may be exposed!"
        else
            log_info "No source maps found"
        fi
    fi

    # ─── v3: jsluice — advanced endpoint + secret extraction ───
    touch "$js_dir/jsluice_urls.txt" "$js_dir/jsluice_secrets.txt"
    if [[ "$ENABLE_DEEP_JS" == "true" ]] && command -v jsluice &>/dev/null; then
        log_info "Running jsluice for deep JS analysis..."
        if compgen -G "$js_dir/files/*.js" >/dev/null 2>&1; then
            # Extract URLs/endpoints
            for f in "$js_dir/files/"*.js; do
                [[ -f "$f" ]] || continue
                jsluice urls "$f" 2>/dev/null | jq -r '.url // empty' 2>/dev/null \
                    >> "$js_dir/jsluice_urls.txt" || true
            done
            sort -u -o "$js_dir/jsluice_urls.txt" "$js_dir/jsluice_urls.txt"

            # Extract secrets
            for f in "$js_dir/files/"*.js; do
                [[ -f "$f" ]] || continue
                jsluice secrets "$f" 2>/dev/null \
                    >> "$js_dir/jsluice_secrets.txt" || true
            done
            sort -u -o "$js_dir/jsluice_secrets.txt" "$js_dir/jsluice_secrets.txt"

            local jsluice_urls jsluice_secs
            jsluice_urls=$(wc -l < "$js_dir/jsluice_urls.txt" 2>/dev/null || echo "0")
            jsluice_secs=$(wc -l < "$js_dir/jsluice_secrets.txt" 2>/dev/null || echo "0")
            log_success "jsluice: $jsluice_urls endpoints, $jsluice_secs potential secrets"
        fi
    else
        [[ "$ENABLE_DEEP_JS" == "true" ]] && log_warn "jsluice not available — using fallback analysis"
    fi

    # LinkFinder — endpoint extraction (v2 original)
    touch "$js_dir/linkfinder_results.txt"
    if [[ -d "$TOOLS_DIR/LinkFinder" ]] && python3 -c 'import jsbeautifier' 2>/dev/null; then
        log_info "Running LinkFinder on downloaded JS files..."
        for f in "$js_dir/files/"*.js; do
            [[ -f "$f" ]] || continue
            python3 "$TOOLS_DIR/LinkFinder/linkfinder.py" -i "$f" -o cli \
                >> "$js_dir/linkfinder_results.txt" 2>> "$LOG_DIR/errors.log" || true
        done
        sort -u -o "$js_dir/linkfinder_results.txt" "$js_dir/linkfinder_results.txt"
        log_success "LinkFinder: $(wc -l < "$js_dir/linkfinder_results.txt") endpoints extracted"
    else
        log_warn "LinkFinder not available or jsbeautifier missing — skipping"
    fi

    # SecretFinder — secrets detection (v2 original)
    touch "$js_dir/secrets_found.txt"
    if [[ -d "$TOOLS_DIR/SecretFinder" ]] && python3 -c 'import jsbeautifier' 2>/dev/null; then
        log_info "Running SecretFinder on downloaded JS files..."
        for f in "$js_dir/files/"*.js; do
            [[ -f "$f" ]] || continue
            python3 "$TOOLS_DIR/SecretFinder/SecretFinder.py" -i "$f" -o cli \
                >> "$js_dir/secrets_found.txt" 2>> "$LOG_DIR/errors.log" || true
        done
        sort -u -o "$js_dir/secrets_found.txt" "$js_dir/secrets_found.txt"
        local secrets_count
        secrets_count=$(wc -l < "$js_dir/secrets_found.txt" 2>/dev/null || echo "0")
        if [[ "$secrets_count" -gt 0 ]]; then
            log_success "SecretFinder: $secrets_count potential secrets found!"
        else
            log_info "SecretFinder: no secrets detected"
        fi
    else
        log_warn "SecretFinder not available — skipping"
    fi

    # ─── v3: Deep grep extraction (enhanced) ───
    log_info "Running deep keyword extraction on JS files..."
    touch "$js_dir/grep_extracts.txt" "$js_dir/internal_ips.txt" "$js_dir/api_routes.txt" "$js_dir/dom_sinks.txt"
    if [[ -d "$js_dir/files" ]] && compgen -G "$js_dir/files/*.js" >/dev/null 2>&1; then
        # Extract URLs
        grep -rhoP 'https?://[^\s"'\''<>]+' "$js_dir/files/" 2>/dev/null | sort -u >> "$js_dir/grep_extracts.txt"

        # Extract potential secrets (API keys, tokens, etc.)
        grep -rhoiE '(api[_-]?key|api[_-]?secret|token|auth[_-]?token|bearer|jwt|access[_-]?key|password|secret[_-]?key|client[_-]?secret)["\\s]*[:=]["\\s]*[A-Za-z0-9_\-\.]{8,}' \
            "$js_dir/files/" 2>/dev/null | sort -u >> "$js_dir/grep_extracts.txt"

        # v3: Internal IPs
        grep -rhoE '(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})' \
            "$js_dir/files/" 2>/dev/null | sort -u > "$js_dir/internal_ips.txt"

        # v3: API routes
        grep -rhoE '["'\''](/api/[^"'\''\\s]{2,}|/v[0-9]+/[^"'\''\\s]{2,}|/graphql[^"'\''\\s]*|/internal/[^"'\''\\s]{2,}|/admin/[^"'\''\\s]{2,})["'\'']' \
            "$js_dir/files/" 2>/dev/null | tr -d '"'"'" | sort -u > "$js_dir/api_routes.txt"

        # v3: DOM sinks (potential XSS vectors)
        grep -rnE '(\.innerHTML|document\.write|eval\(|setTimeout\(|setInterval\(|\.outerHTML|document\.location|window\.location\s*=|postMessage)' \
            "$js_dir/files/" 2>/dev/null | head -200 > "$js_dir/dom_sinks.txt"

        local ip_count api_count sink_count
        ip_count=$(wc -l < "$js_dir/internal_ips.txt" 2>/dev/null || echo "0")
        api_count=$(wc -l < "$js_dir/api_routes.txt" 2>/dev/null || echo "0")
        sink_count=$(wc -l < "$js_dir/dom_sinks.txt" 2>/dev/null || echo "0")
        [[ "$ip_count" -gt 0 ]] && log_success "🔍 Found $ip_count internal IP addresses in JS!"
        [[ "$api_count" -gt 0 ]] && log_success "🔍 Found $api_count API routes in JS!"
        [[ "$sink_count" -gt 0 ]] && log_success "🔍 Found $sink_count DOM XSS sinks in JS!"
    fi

    local total_endpoints
    total_endpoints=$(cat "$js_dir/linkfinder_results.txt" "$js_dir/grep_extracts.txt" "$js_dir/jsluice_urls.txt" 2>/dev/null | sort -u | wc -l)
    log_success "JS analysis complete: $dl_count files, $total_endpoints endpoints/secrets"

    discord_notify_results "JS Discovery" "$dl_count files, $total_endpoints endpoints"
    save_checkpoint "stage_js_analysis"
}

# ─── STAGE 10: PARAMETER DISCOVERY ──────────────────────────
stage_params() {
    log_stage "Parameter Discovery"

    local urls_file="$OUTPUT_DIR/urls/inscope_urls.txt"
    local endpoints_dir="$OUTPUT_DIR/endpoints"

    touch "$endpoints_dir/all_endpoints.txt" "$endpoints_dir/paramspider_out.txt"

    if [[ ! -s "$urls_file" ]]; then
        log_warn "No in-scope URLs — skipping parameter discovery"
        save_checkpoint "stage_params"
        return 1
    fi

    # ParamSpider
    if command -v paramspider &>/dev/null; then
        log_info "Running ParamSpider..."
        local target_for_param="${DOMAIN:-$(head -1 "$urls_file" | unfurl domain 2>/dev/null || head -1 "$urls_file")}"
        safe_run "ParamSpider" \
            "paramspider -d '$target_for_param'" || true
        # ParamSpider outputs to results/<domain>.txt or output/ folder
        if [[ -d "results" ]]; then
            find results/ -name "*.txt" -exec cat {} + >> "$endpoints_dir/paramspider_out.txt" 2>/dev/null
            rm -rf results/
        fi
        if [[ -d "output" ]]; then
            find output/ -name "*.txt" -exec cat {} + >> "$endpoints_dir/paramspider_out.txt" 2>/dev/null
            rm -rf output/
        fi
    else
        log_warn "ParamSpider not available — skipping"
    fi

    # Arjun — test top endpoints for hidden params
    mkdir -p "$endpoints_dir/arjun"
    if command -v arjun &>/dev/null; then
        log_info "Running Arjun on top parameterized endpoints..."
        local arjun_targets
        arjun_targets=$(head -30 "$urls_file" | grep '?' | head -15)
        if [[ -n "$arjun_targets" ]]; then
            local arjun_idx=0
            while IFS= read -r url; do
                arjun_idx=$((arjun_idx + 1))
                log_info "Arjun [$arjun_idx]: $url"
                timeout "$ARJUN_TIMEOUT" arjun -u "$url" -oJ "$endpoints_dir/arjun/result_${arjun_idx}.json" \
                    >> "$LOG_DIR/recon.log" 2>> "$LOG_DIR/errors.log" || true
            done <<< "$arjun_targets"
            log_success "Arjun scan completed ($arjun_idx URLs tested)"
        else
            log_info "No parameterized URLs found for Arjun — skipping"
        fi
    else
        log_warn "Arjun not available — skipping"
    fi

    # Merge all endpoints
    cat "$OUTPUT_DIR/js/linkfinder_results.txt" \
        "$OUTPUT_DIR/js/grep_extracts.txt" \
        "$OUTPUT_DIR/js/jsluice_urls.txt" \
        "$endpoints_dir/paramspider_out.txt" \
        2>/dev/null | sort -u > "$endpoints_dir/all_endpoints.txt"

    local count
    count=$(wc -l < "$endpoints_dir/all_endpoints.txt" 2>/dev/null || echo "0")
    log_success "Endpoint discovery complete: $count total endpoints"

    discord_notify_results "Endpoint Discovery" "$count"
    save_checkpoint "stage_params"
}

# ─── STAGE 11: GF PATTERN MATCHING ──────────────────────────
stage_patterns() {
    log_stage "Pattern-Based Vulnerability Fingerprinting"

    local urls_file="$OUTPUT_DIR/urls/inscope_urls.txt"
    local params_dir="$OUTPUT_DIR/params"

    if [[ ! -s "$urls_file" ]]; then
        log_warn "No in-scope URLs — skipping gf patterns"
        save_checkpoint "stage_patterns"
        return 1
    fi

    if ! command -v gf &>/dev/null; then
        log_warn "gf not available — skipping pattern matching"
        save_checkpoint "stage_patterns"
        return 1
    fi

    local patterns=("xss" "sqli" "ssrf" "lfi" "redirect" "idor" "interestingparams")
    local pattern_files=("xss" "sqli" "ssrf" "lfi" "redirect" "idor" "interesting")

    for i in "${!patterns[@]}"; do
        local pattern="${patterns[$i]}"
        local outfile="${pattern_files[$i]}"
        cat "$urls_file" | gf "$pattern" > "$params_dir/${outfile}.txt" 2>/dev/null || true
        local count
        count=$(wc -l < "$params_dir/${outfile}.txt" 2>/dev/null || echo "0")
        if [[ "$count" -gt 0 ]]; then
            log_success "gf:$pattern → $count matches"
        fi
    done

    # Also try debug_logic if pattern exists
    cat "$urls_file" | gf debug_logic > "$params_dir/debug.txt" 2>/dev/null || true

    log_success "Pattern matching complete"
    save_checkpoint "stage_patterns"
}

# ─── STAGE 12: SUBDOMAIN TAKEOVER DETECTION ─────────────────
stage_takeover() {
    log_stage "Subdomain Takeover Detection"

    if [[ "$ENABLE_TAKEOVER" != "true" ]]; then
        log_info "Takeover detection disabled"
        save_checkpoint "stage_takeover"
        return 0
    fi

    local subs_file="$OUTPUT_DIR/subdomains/all.txt"
    local takeover_dir="$OUTPUT_DIR/takeover"
    mkdir -p "$takeover_dir"

    if [[ ! -s "$subs_file" ]]; then
        log_warn "No subdomains — skipping takeover detection"
        save_checkpoint "stage_takeover"
        return 1
    fi

    # subzy — fast subdomain takeover checker
    if command -v subzy &>/dev/null; then
        log_info "Running subzy for subdomain takeover detection..."
        timeout "$STAGE_TIMEOUT" subzy run --targets "$subs_file" \
            --concurrency 20 \
            --hide_fails \
            --timeout 15 \
            > "$takeover_dir/subzy_results.txt" 2>> "$LOG_DIR/errors.log" &
        wait $! || {
            log_warn "subzy timed out or failed"
            FAILED_STAGES+=("subzy")
        }

        # Check for vulnerable findings
        if [[ -f "$takeover_dir/subzy_results.txt" ]]; then
            local vuln_count
            vuln_count=$(grep -ci 'VULNERABLE' "$takeover_dir/subzy_results.txt" 2>/dev/null || echo "0")
            if [[ "$vuln_count" -gt 0 ]]; then
                log_success "🔥🔥 SUBDOMAIN TAKEOVER: $vuln_count vulnerable subdomain(s) found!"
                discord_notify "🔥🔥 **SUBDOMAIN TAKEOVER**: $vuln_count vulnerable subdomain(s) found! Check takeover/subzy_results.txt"
            else
                log_info "subzy: no takeover vulnerabilities found"
            fi
        fi
    else
        log_warn "subzy not available — skipping"
    fi

    # Also run nuclei with takeover templates if available
    if command -v nuclei &>/dev/null; then
        log_info "Running nuclei takeover templates..."
        timeout "$STAGE_TIMEOUT" nuclei -l "$subs_file" \
            -t takeovers/ \
            -silent \
            -o "$takeover_dir/nuclei_takeover.txt" \
            >> "$LOG_DIR/recon.log" 2>> "$LOG_DIR/errors.log" &
        wait $! || log_warn "nuclei takeover templates timed out"

        local nuclei_tk_count
        nuclei_tk_count=$(wc -l < "$takeover_dir/nuclei_takeover.txt" 2>/dev/null || echo "0")
        [[ "$nuclei_tk_count" -gt 0 ]] && log_success "nuclei takeover: $nuclei_tk_count finding(s)"
    fi

    # Copy CNAME data for reference
    [[ -f "$OUTPUT_DIR/subdomains/cnames.txt" ]] && cp "$OUTPUT_DIR/subdomains/cnames.txt" "$takeover_dir/cname_map.txt"

    save_checkpoint "stage_takeover"
}

# ─── STAGE 13: CORS MISCONFIGURATION SCANNING ───────────────
stage_cors() {
    log_stage "CORS Misconfiguration Scanning"

    if [[ "$ENABLE_CORS" != "true" ]]; then
        log_info "CORS scanning disabled"
        save_checkpoint "stage_cors"
        return 0
    fi

    local live_hosts="$OUTPUT_DIR/subdomains/live_hosts.txt"
    local vulns_dir="$OUTPUT_DIR/vulns"
    mkdir -p "$vulns_dir"

    if [[ ! -s "$live_hosts" ]]; then
        log_warn "No live hosts — skipping CORS scan"
        save_checkpoint "stage_cors"
        return 1
    fi

    # Corsy — CORS misconfiguration scanner
    if [[ -d "$TOOLS_DIR/Corsy" ]]; then
        log_info "Running Corsy CORS scanner..."
        timeout "$STAGE_TIMEOUT" python3 "$TOOLS_DIR/Corsy/corsy.py" \
            -i "$live_hosts" \
            -o "$vulns_dir/cors_results.json" \
            -t "$THREADS" \
            >> "$LOG_DIR/recon.log" 2>> "$LOG_DIR/errors.log" &
        wait $! || {
            log_warn "Corsy timed out or failed"
            FAILED_STAGES+=("Corsy")
        }

        if [[ -f "$vulns_dir/cors_results.json" ]]; then
            # Extract vulnerable hosts
            jq -r 'to_entries[] | select(.value | length > 0) | .key' \
                "$vulns_dir/cors_results.json" > "$vulns_dir/cors_vulnerable.txt" 2>/dev/null || true
            local cors_count
            cors_count=$(wc -l < "$vulns_dir/cors_vulnerable.txt" 2>/dev/null || echo "0")
            if [[ "$cors_count" -gt 0 ]]; then
                log_success "🔥 CORS misconfiguration found on $cors_count host(s)!"
                discord_notify "🔥 **CORS misconfig** found on $cors_count host(s)!"
            else
                log_info "Corsy: no CORS misconfigurations detected"
            fi
        fi
    else
        # Fallback: simple CORS check via curl
        log_info "Corsy not available — running simple CORS check..."
        touch "$vulns_dir/cors_vulnerable.txt"
        local cors_check_count=0
        while IFS= read -r host; do
            [[ -z "$host" ]] && continue
            cors_check_count=$((cors_check_count + 1))
            [[ $cors_check_count -gt 30 ]] && break
            local response
            response=$(curl -s -m 5 -I -H "Origin: https://evil.com" "$host" 2>/dev/null || true)
            if echo "$response" | grep -qi 'access-control-allow-origin.*evil.com'; then
                echo "$host" >> "$vulns_dir/cors_vulnerable.txt"
                log_success "CORS reflected origin: $host"
            fi
        done < "$live_hosts"
    fi

    save_checkpoint "stage_cors"
}

# ─── STAGE 14: CLOUD BUCKET ENUMERATION ─────────────────────
stage_cloud() {
    log_stage "Cloud Bucket Enumeration"

    if [[ "$ENABLE_CLOUD" != "true" ]]; then
        log_info "Cloud enumeration disabled — use --cloud flag to enable"
        save_checkpoint "stage_cloud"
        return 0
    fi

    local cloud_dir="$OUTPUT_DIR/cloud"
    mkdir -p "$cloud_dir"

    # Build keywords from domain
    local keywords=()
    if [[ -n "$DOMAIN" ]]; then
        # Extract base name from domain (e.g., "example" from "example.com")
        local base_name
        base_name=$(echo "$DOMAIN" | sed 's/\.[^.]*$//')
        keywords+=("$base_name")
        keywords+=("$DOMAIN")
    elif [[ -f "$TARGET_FILE" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local bn
            bn=$(echo "$line" | sed 's/\.[^.]*$//')
            keywords+=("$bn")
        done < "$TARGET_FILE"
    fi

    if [[ ${#keywords[@]} -eq 0 ]]; then
        log_warn "No keywords for cloud enumeration"
        save_checkpoint "stage_cloud"
        return 1
    fi

    if [[ -d "$TOOLS_DIR/cloud_enum" ]]; then
        log_info "Running cloud_enum for S3/Azure/GCP bucket discovery..."
        local keyword_args=""
        for kw in "${keywords[@]}"; do
            keyword_args="$keyword_args -k $kw"
        done

        timeout "$STAGE_TIMEOUT" python3 "$TOOLS_DIR/cloud_enum/cloud_enum.py" \
            $keyword_args \
            -l "$cloud_dir/cloud_findings.txt" \
            -t "$THREADS" \
            >> "$LOG_DIR/recon.log" 2>> "$LOG_DIR/errors.log" &
        wait $! || {
            log_warn "cloud_enum timed out or failed"
            FAILED_STAGES+=("cloud_enum")
        }

        local cloud_count
        cloud_count=$(wc -l < "$cloud_dir/cloud_findings.txt" 2>/dev/null || echo "0")
        if [[ "$cloud_count" -gt 0 ]]; then
            log_success "☁️ Cloud enum found $cloud_count result(s)"
            discord_notify_results "Cloud Enumeration" "$cloud_count"
        else
            log_info "cloud_enum: no public buckets found"
        fi
    else
        log_warn "cloud_enum not available — skipping"
    fi

    save_checkpoint "stage_cloud"
}

# ─── STAGE 15: GITHUB DORKING & SECRET SCANNING ─────────────
stage_github() {
    log_stage "GitHub Secret Scanning"

    if [[ "$ENABLE_GITHUB" != "true" ]]; then
        log_info "GitHub scanning disabled — use --github flag to enable"
        save_checkpoint "stage_github"
        return 0
    fi

    local secrets_dir="$OUTPUT_DIR/secrets"
    mkdir -p "$secrets_dir"

    # trufflehog — scan for secrets on GitHub
    if command -v trufflehog &>/dev/null; then
        local target_keyword="${DOMAIN:-}"
        if [[ -z "$target_keyword" ]] && [[ -f "$TARGET_FILE" ]]; then
            target_keyword=$(head -1 "$TARGET_FILE")
        fi

        if [[ -n "$target_keyword" ]]; then
            log_info "Running trufflehog to scan for exposed secrets..."

            # Scan GitHub org if it looks like an org name
            local base_name
            base_name=$(echo "$target_keyword" | sed 's/\.[^.]*$//')

            if [[ -n "$GITHUB_TOKEN" ]]; then
                log_info "Scanning GitHub org: $base_name"
                timeout "$STAGE_TIMEOUT" trufflehog github \
                    --org="$base_name" \
                    --token="$GITHUB_TOKEN" \
                    --only-verified \
                    --json \
                    > "$secrets_dir/trufflehog_results.json" 2>> "$LOG_DIR/errors.log" &
                wait $! || {
                    log_warn "trufflehog timed out or failed"
                    FAILED_STAGES+=("trufflehog")
                }
            else
                log_warn "GITHUB_TOKEN not set — trufflehog will have limited API access"
                log_info "Set GITHUB_TOKEN env var for full GitHub scanning capability"
                # Try scanning without token (very limited)
                timeout 120 trufflehog github \
                    --org="$base_name" \
                    --only-verified \
                    --json \
                    > "$secrets_dir/trufflehog_results.json" 2>> "$LOG_DIR/errors.log" || true
            fi

            if [[ -f "$secrets_dir/trufflehog_results.json" ]]; then
                local secret_count
                secret_count=$(wc -l < "$secrets_dir/trufflehog_results.json" 2>/dev/null || echo "0")
                if [[ "$secret_count" -gt 0 ]]; then
                    log_success "🔥🔥 trufflehog found $secret_count VERIFIED secret(s)!"
                    discord_notify "🔥🔥 **trufflehog found $secret_count VERIFIED secret(s)**! Check secrets/ directory!"
                else
                    log_info "trufflehog: no verified secrets found"
                fi
            fi
        fi
    else
        log_warn "trufflehog not available — skipping GitHub scanning"
    fi

    save_checkpoint "stage_github"
}

# ─── STAGE 16: NUCLEI VULNERABILITY SCAN ────────────────────
stage_nuclei() {
    log_stage "Nuclei Vulnerability Scan"

    if [[ "$ENABLE_NUCLEI" != "true" ]]; then
        log_info "Nuclei scanning disabled — use -n flag to enable"
        save_checkpoint "stage_nuclei"
        return 0
    fi

    local live_hosts="$OUTPUT_DIR/subdomains/live_hosts.txt"

    if [[ ! -s "$live_hosts" ]]; then
        log_warn "No live hosts — skipping nuclei scan"
        save_checkpoint "stage_nuclei"
        return 1
    fi

    if ! command -v nuclei &>/dev/null; then
        log_error "nuclei not available — skipping"
        save_checkpoint "stage_nuclei"
        return 1
    fi

    # Update nuclei templates first
    log_info "Updating nuclei templates..."
    nuclei -ut >> "$LOG_DIR/install.log" 2>&1 || true

    log_info "Running nuclei (critical+high severity, rate-limited)..."
    timeout "$STAGE_TIMEOUT" nuclei -l "$live_hosts" -s critical,high -rl 10 -bs 5 -c 3 -silent -o "$LOG_DIR/nuclei_findings.txt" \
        >> "$LOG_DIR/recon.log" 2>> "$LOG_DIR/errors.log" &
    wait $! || {
        log_warn "nuclei timed out or failed"
        FAILED_STAGES+=("nuclei")
    }

    local count
    count=$(wc -l < "$LOG_DIR/nuclei_findings.txt" 2>/dev/null || echo "0")
    if [[ "$count" -gt 0 ]]; then
        log_success "🔥 Nuclei found $count findings!"
        discord_notify "🔥 Nuclei found **$count** critical/high findings!"
    else
        log_info "Nuclei: no critical/high findings"
    fi
    save_checkpoint "stage_nuclei"
}

# ─── STAGE 17: OUT-OF-BAND TESTING ──────────────────────────
stage_oob() {
    log_stage "Out-of-Band Blind Testing"

    # This stage just sets up interactsh and gives the user the URL
    # Actual blind injection requires manual or semi-automated testing

    if ! command -v interactsh-client &>/dev/null; then
        log_info "interactsh-client not available — skipping OOB setup"
        save_checkpoint "stage_oob"
        return 0
    fi

    local oob_dir="$OUTPUT_DIR/oob"
    mkdir -p "$oob_dir"

    log_info "Generating interactsh URL for blind testing..."
    # Generate an interactsh URL and save it for the user
    timeout 15 interactsh-client -n 1 -json \
        > "$oob_dir/interactsh_url.txt" 2>> "$LOG_DIR/errors.log" &
    local pid=$!
    sleep 5
    kill "$pid" 2>/dev/null || true

    if [[ -s "$oob_dir/interactsh_url.txt" ]]; then
        local oob_url
        oob_url=$(jq -r '.["interactsh-url"] // empty' "$oob_dir/interactsh_url.txt" 2>/dev/null | head -1)
        if [[ -n "$oob_url" ]]; then
            log_success "Interactsh URL generated: $oob_url"
            log_info "Use this URL for blind SSRF/XSS testing. Monitor with: interactsh-client"
            echo "$oob_url" > "$oob_dir/blind_testing_url.txt"
        fi
    else
        log_info "Interactsh setup skipped — run manually: interactsh-client"
    fi

    save_checkpoint "stage_oob"
}

# ─── STAGE 18: CLEANUP ──────────────────────────────────────
stage_cleanup() {
    log_stage "Cleaning Up Intermediate Files"

    local freed_before freed_after saved
    freed_before=$(du -sm "$OUTPUT_DIR" 2>/dev/null | awk '{print $1}')

    # ═══════════════════════════════════════════════════════════
    # WHAT WE KEEP (all original recon data):
    #
    #   subdomains/  → all.txt              (final merged subdomains)
    #                  live_hosts.txt        (URLs of responding hosts)
    #                  live_details.csv      (httpx: status, title, tech, CL)
    #                  ips.txt               (A records from dnsx)
    #                  cnames.txt            (CNAME records from dnsx)
    #
    #   urls/        → all_urls.txt          (all discovered URLs pre-scope)
    #                  inscope_urls.txt       (scope-filtered URLs)
    #
    #   ports/       → open_ports.txt        (ip:port from masscan)
    #                  interesting_ports.txt  (non-80/443)
    #                  nmap_results.txt       (service detection)
    #                  nmap_results.xml       (nmap XML for parsers)
    #
    #   tech/        → fingerprints.txt      (whatweb summary)
    #                  waf_results.txt        (wafw00f output)
    #
    #   screenshots/ → *.png/jpg             (gowitness captures)
    #
    #   js/          → js_urls.txt           (all JS file URLs)
    #                  files/                (downloaded JS for manual review)
    #                  url_map.txt           (hash→URL mapping)
    #                  sourcemaps/           (found .js.map files)
    #                  sourcemap_urls.txt    (map URL→file mapping)
    #                  linkfinder_results.txt (endpoints from LinkFinder)
    #                  secrets_found.txt     (secrets from SecretFinder)
    #                  jsluice_urls.txt      (endpoints from jsluice)
    #                  jsluice_secrets.txt   (secrets from jsluice)
    #                  grep_extracts.txt     (regex-extracted URLs/keys)
    #                  internal_ips.txt      (10.x/172.x/192.168.x)
    #                  api_routes.txt        (/api/, /v1/, /internal/)
    #                  dom_sinks.txt         (innerHTML, eval, etc.)
    #
    #   endpoints/   → all_endpoints.txt     (merged from all sources)
    #                  arjun/                (hidden param results)
    #
    #   params/      → xss.txt, sqli.txt, ssrf.txt, lfi.txt,
    #                  redirect.txt, idor.txt, interesting.txt, debug.txt
    #
    #   fuzzing/     → all_findings.txt      (merged ffuf summary)
    #                  ffuf_*.json           (detailed per-host results)
    #
    #   takeover/    → subzy_results.txt     (takeover findings)
    #                  nuclei_takeover.txt   (nuclei takeover checks)
    #                  cname_map.txt         (CNAME data for context)
    #
    #   vulns/       → cors_results.json     (full Corsy output)
    #                  cors_vulnerable.txt   (vulnerable hosts)
    #
    #   cloud/       → cloud_findings.txt    (S3/Azure/GCP results)
    #
    #   secrets/     → trufflehog_results.json (verified secrets)
    #
    #   oob/         → blind_testing_url.txt (interactsh URL)
    #                  interactsh_url.txt    (raw interactsh output)
    #
    #   logs/        → recon.log, errors.log, install.log,
    #                  summary.txt, nuclei_findings.txt
    # ═══════════════════════════════════════════════════════════

    # ─── subdomains/ ───
    # resolved.txt content was already copied into all.txt (line 907)
    rm -f "$OUTPUT_DIR/subdomains/resolved.txt"

    # ─── urls/ ───
    # domains_only.txt = temp extraction of bare domains for gau/waybackurls
    rm -f "$OUTPUT_DIR/urls/domains_only.txt"
    # katana_out.txt = already merged into all_urls.txt→inscope_urls.txt
    rm -f "$OUTPUT_DIR/urls/katana_out.txt"

    # ─── ports/ ───
    # masscan_raw.txt = grepable output already parsed into open_ports.txt
    rm -f "$OUTPUT_DIR/ports/masscan_raw.txt"
    # nmap_targets.txt = temp IP list built from open_ports.txt for nmap -iL
    rm -f "$OUTPUT_DIR/ports/nmap_targets.txt"

    # ─── tech/ ───
    # whatweb_raw.jsonl = raw JSONL already parsed into fingerprints.txt
    rm -f "$OUTPUT_DIR/tech/whatweb_raw.jsonl"

    # ─── js/ ───
    # Everything kept. Only remove empty sourcemaps/ if no maps were found
    local sm_count
    sm_count=$(find "$OUTPUT_DIR/js/sourcemaps" -type f 2>/dev/null | wc -l)
    if [[ "$sm_count" -eq 0 ]]; then
        rm -rf "$OUTPUT_DIR/js/sourcemaps"
    fi

    # ─── endpoints/ ───
    # paramspider_out.txt = already merged into all_endpoints.txt
    rm -f "$OUTPUT_DIR/endpoints/paramspider_out.txt"
    # Remove arjun/ only if it's empty (no results found)
    if [[ -d "$OUTPUT_DIR/endpoints/arjun" ]]; then
        local arjun_count
        arjun_count=$(find "$OUTPUT_DIR/endpoints/arjun" -type f 2>/dev/null | wc -l)
        if [[ "$arjun_count" -eq 0 ]]; then
            rm -rf "$OUTPUT_DIR/endpoints/arjun"
        fi
    fi

    # ─── Final sweep ───
    # Remove empty directories (e.g., ports/ if port scan was disabled)
    find "$OUTPUT_DIR" -type d -empty -delete 2>/dev/null || true
    # Remove 0-byte files except logs (empty results = just clutter)
    find "$OUTPUT_DIR" -maxdepth 2 -type f -empty ! -path '*/logs/*' -delete 2>/dev/null || true

    freed_after=$(du -sm "$OUTPUT_DIR" 2>/dev/null | awk '{print $1}')
    saved=$(( ${freed_before:-0} - ${freed_after:-0} ))
    if [[ "$saved" -gt 0 ]]; then
        log_success "Cleanup freed ${saved}MB of intermediate files"
    else
        log_success "Cleanup complete (output was already lean)"
    fi

    save_checkpoint "stage_cleanup"
}

# ─── STAGE 19: SUMMARY ──────────────────────────────────────
stage_summary() {
    log_stage "Generating Summary"

    local end_time
    end_time=$(date +%s)
    local elapsed=$(( end_time - SCRIPT_START ))
    local duration
    duration="$(( elapsed / 60 ))m $(( elapsed % 60 ))s"

    # Count results
    local subs live urls jsfiles endpoints params ports_count
    local tech_count takeover_count cors_count fuzz_count secrets_count
    subs=$(wc -l < "$OUTPUT_DIR/subdomains/all.txt" 2>/dev/null || echo "0")
    live=$(wc -l < "$OUTPUT_DIR/subdomains/live_hosts.txt" 2>/dev/null || echo "0")
    urls=$(wc -l < "$OUTPUT_DIR/urls/inscope_urls.txt" 2>/dev/null || echo "0")
    jsfiles=$(wc -l < "$OUTPUT_DIR/js/js_urls.txt" 2>/dev/null || echo "0")
    endpoints=$(wc -l < "$OUTPUT_DIR/endpoints/all_endpoints.txt" 2>/dev/null || echo "0")
    params=$(cat "$OUTPUT_DIR/params/"*.txt 2>/dev/null | sort -u | wc -l || echo "0")
    ports_count=$(wc -l < "$OUTPUT_DIR/ports/open_ports.txt" 2>/dev/null || echo "0")
    tech_count=$(wc -l < "$OUTPUT_DIR/tech/fingerprints.txt" 2>/dev/null || echo "0")
    takeover_count=$(grep -ci 'VULNERABLE' "$OUTPUT_DIR/takeover/subzy_results.txt" 2>/dev/null || echo "0")
    cors_count=$(wc -l < "$OUTPUT_DIR/vulns/cors_vulnerable.txt" 2>/dev/null || echo "0")
    fuzz_count=$(wc -l < "$OUTPUT_DIR/fuzzing/all_findings.txt" 2>/dev/null || echo "0")
    secrets_count=$(wc -l < "$OUTPUT_DIR/secrets/trufflehog_results.json" 2>/dev/null || echo "0")

    local failed_str="None"
    if [[ ${#FAILED_STAGES[@]} -gt 0 ]]; then
        failed_str=$(IFS=', '; echo "${FAILED_STAGES[*]}")
    fi

    # Write summary file
    cat > "$LOG_DIR/summary.txt" << EOFSUMMARY
═══════════════════════════════════════════════════════
  ORSURECON v3 SUMMARY — $(date '+%d-%m-%Y %H:%M:%S')
═══════════════════════════════════════════════════════

  Target:          ${DOMAIN:-$TARGET_FILE}
  Mode:            $MODE
  Duration:        $duration
  Host:            $(hostname 2>/dev/null || echo "unknown")

  ─────────────────────────────────────────────────────
  DISCOVERY
  ─────────────────────────────────────────────────────

  Subdomains:      $subs
  Live Hosts:      $live
  Open Ports:      $ports_count
  Tech Profiles:   $tech_count

  ─────────────────────────────────────────────────────
  CONTENT
  ─────────────────────────────────────────────────────

  URLs:            $urls
  JS Files:        $jsfiles
  Endpoints:       $endpoints
  Parameters:      $params
  Fuzzed Paths:    $fuzz_count

  ─────────────────────────────────────────────────────
  VULNERABILITIES
  ─────────────────────────────────────────────────────

  Takeover Vulns:  $takeover_count
  CORS Misconfig:  $cors_count
  Leaked Secrets:  $secrets_count

  ─────────────────────────────────────────────────────
  STATUS
  ─────────────────────────────────────────────────────

  Failed Stages:   $failed_str

  ─────────────────────────────────────────────────────
  OUTPUT DIRECTORY
  ─────────────────────────────────────────────────────

  $OUTPUT_DIR/

═══════════════════════════════════════════════════════
EOFSUMMARY

    # Display summary
    echo ""
    cat "$LOG_DIR/summary.txt"
    echo ""

    # Discord final summary
    discord_notify_summary "$duration" "$subs" "$live" "$urls" "$jsfiles" "$endpoints" "$params" "$failed_str"
}

# ─── USAGE / HELP ────────────────────────────────────────────
show_help() {
    echo ""
    echo -e "${BOLD}Usage:${NC}"
    echo "  recon.sh <domain> [options]"
    echo "  recon.sh -l <file> [options]"
    echo ""
    echo -e "${BOLD}Modes:${NC}"
    echo "  <domain>             Single domain recon (e.g., example.com)"
    echo "  -l, --list <file>    Process a list of domains (enumerates subdomains first)"
    echo "  -l <file> -ns        Process a list of explicit targets (no subdomain enum)"
    echo ""
    echo -e "${BOLD}Core Options:${NC}"
    echo "  -o, --output <dir>   Output directory (default: ./recon-output)"
    echo "  -n, --nuclei         Enable nuclei vulnerability scanning"
    echo "  -s, --skip-install   Skip tool installation checks"
    echo "  -ns, --no-subs       Skip subdomain enumeration (use with -l)"
    echo "  --install            Install all dependencies and exit"
    echo "  --check              Verify tool installation and exit"
    echo "  --timeout <sec>      Per-stage timeout in seconds (default: 300)"
    echo "  --threads <n>        Thread count for tools (default: 5)"
    echo "  --fresh              Ignore checkpoint — restart from scratch"
    echo "  --rate-delay <sec>   Delay between API-heavy tools (default: 5)"
    echo ""
    echo -e "${BOLD}v3 Feature Flags:${NC}"
    echo "  --ports              Enable port scanning (masscan + nmap)"
    echo "  --fuzz               Enable directory/content fuzzing (ffuf)"
    echo "  --deep-js            Enable deep JS analysis — source maps, jsluice (default: on)"
    echo "  --no-deep-js         Disable deep JS analysis"
    echo "  --takeover           Enable subdomain takeover detection (default: on)"
    echo "  --no-takeover        Disable subdomain takeover detection"
    echo "  --cors               Enable CORS misconfiguration scanning (default: on)"
    echo "  --no-cors            Disable CORS scanning"
    echo "  --cloud              Enable cloud bucket enumeration (S3/Azure/GCP)"
    echo "  --github             Enable GitHub secret scanning (set GITHUB_TOKEN)"
    echo "  --screenshots        Enable screenshot capture (default: on)"
    echo "  --no-screenshots     Disable screenshots"
    echo "  --all                Enable ALL optional features"
    echo "  --stealth            Passive-only mode — no active scanning/fuzzing"
    echo "  --wordlist <path>    Custom wordlist for ffuf fuzzing"
    echo ""
    echo -e "${BOLD}Environment:${NC}"
    echo "  DISCORD_WEBHOOK      Discord webhook URL for notifications"
    echo "  GITHUB_TOKEN         GitHub personal access token for secret scanning"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  ./recon.sh example.com                       # Standard recon (default stages)"
    echo "  ./recon.sh example.com --all                 # Full recon with all features"
    echo "  ./recon.sh example.com --ports --fuzz        # Add port scanning + fuzzing"
    echo "  ./recon.sh -l domains.txt                    # Enum subs for each domain"
    echo "  ./recon.sh -l targets.txt -ns                # No sub enum — scan as-is"
    echo "  ./recon.sh example.com --stealth             # Passive-only recon"
    echo "  ./recon.sh example.com --github --cloud      # Add GitHub + cloud scanning"
    echo ""
    echo -e "${BOLD}Default ON:${NC}  deep-js, takeover, cors, screenshots"
    echo -e "${BOLD}Default OFF:${NC} nuclei, ports, fuzz, cloud, github, stealth"
    echo ""
    echo -e "  -h, --help           Show this help message"
    echo ""
}

# ─── ARGUMENT PARSING ───────────────────────────────────────
parse_args() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -l|--list)
                if [[ $# -lt 2 ]]; then
                    echo -e "${RED}[✗] Error: -l/--list requires a filename argument${NC}"
                    exit 1
                fi
                MODE="list"
                TARGET_FILE="$2"
                if [[ -z "$TARGET_FILE" ]] || [[ ! -f "$TARGET_FILE" ]]; then
                    echo -e "${RED}[✗] Error: List file '$TARGET_FILE' not found${NC}"
                    exit 1
                fi
                shift 2
                ;;
            -o|--output)
                if [[ $# -lt 2 ]]; then
                    echo -e "${RED}[✗] Error: -o/--output requires a directory argument${NC}"
                    exit 1
                fi
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -n|--nuclei)
                ENABLE_NUCLEI=true
                shift
                ;;
            -s|--skip-install)
                SKIP_INSTALL=true
                shift
                ;;
            -ns|--no-subs)
                NO_SUBS=true
                shift
                ;;
            --install)
                MODE="install"
                shift
                ;;
            --check)
                MODE="check"
                shift
                ;;
            --timeout)
                if [[ $# -lt 2 ]]; then
                    echo -e "${RED}[✗] Error: --timeout requires a value${NC}"
                    exit 1
                fi
                STAGE_TIMEOUT="$2"
                shift 2
                ;;
            --fresh)
                FRESH_RUN=true
                shift
                ;;
            --rate-delay)
                if [[ $# -lt 2 ]]; then
                    echo -e "${RED}[✗] Error: --rate-delay requires a value${NC}"
                    exit 1
                fi
                RATE_LIMIT_DELAY="$2"
                shift 2
                ;;
            --threads)
                if [[ $# -lt 2 ]]; then
                    echo -e "${RED}[✗] Error: --threads requires a value${NC}"
                    exit 1
                fi
                THREADS="$2"
                shift 2
                ;;
            # v3 flags
            --ports)
                ENABLE_PORTS=true
                shift
                ;;
            --fuzz)
                ENABLE_FUZZ=true
                shift
                ;;
            --deep-js)
                ENABLE_DEEP_JS=true
                shift
                ;;
            --no-deep-js)
                ENABLE_DEEP_JS=false
                shift
                ;;
            --takeover)
                ENABLE_TAKEOVER=true
                shift
                ;;
            --no-takeover)
                ENABLE_TAKEOVER=false
                shift
                ;;
            --cors)
                ENABLE_CORS=true
                shift
                ;;
            --no-cors)
                ENABLE_CORS=false
                shift
                ;;
            --cloud)
                ENABLE_CLOUD=true
                shift
                ;;
            --github)
                ENABLE_GITHUB=true
                shift
                ;;
            --screenshots)
                ENABLE_SCREENSHOTS=true
                shift
                ;;
            --no-screenshots)
                ENABLE_SCREENSHOTS=false
                shift
                ;;
            --all)
                ENABLE_PORTS=true
                ENABLE_FUZZ=true
                ENABLE_DEEP_JS=true
                ENABLE_TAKEOVER=true
                ENABLE_CORS=true
                ENABLE_CLOUD=true
                ENABLE_GITHUB=true
                ENABLE_SCREENSHOTS=true
                ENABLE_NUCLEI=true
                shift
                ;;
            --stealth)
                ENABLE_STEALTH=true
                ENABLE_PORTS=false
                ENABLE_FUZZ=false
                shift
                ;;
            --wordlist)
                if [[ $# -lt 2 ]]; then
                    echo -e "${RED}[✗] Error: --wordlist requires a path argument${NC}"
                    exit 1
                fi
                FUZZ_WORDLIST="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                echo -e "${RED}[✗] Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
            *)
                if [[ -z "$MODE" ]]; then
                    MODE="domain"
                    DOMAIN="$1"
                fi
                shift
                ;;
        esac
    done

    if [[ -z "$MODE" ]]; then
        echo -e "${RED}[✗] Error: No target specified${NC}"
        show_help
        exit 1
    fi
}

# ─── MAIN ────────────────────────────────────────────────────
main() {
    SCRIPT_START=$(date +%s)

    banner
    parse_args "$@"

    # Handle standalone modes (no target needed)
    if [[ "$MODE" == "install" ]] || [[ "$MODE" == "check" ]]; then
        LOG_DIR="${OUTPUT_DIR}/logs"
        mkdir -p "$LOG_DIR"
        touch "$LOG_DIR/recon.log" "$LOG_DIR/errors.log" "$LOG_DIR/install.log"
        export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin"
        if [[ "$MODE" == "install" ]]; then
            install_all_tools
            verify_tools
            log_success "Installation complete!"
        else
            verify_tools
        fi
        exit 0
    fi

    # Set up output directory
    if [[ "$MODE" == "domain" ]]; then
        OUTPUT_DIR="${OUTPUT_DIR}/${DOMAIN}"
    fi

    # Convert to absolute path so cd in subshells doesn't break log paths
    OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"
    LOG_DIR="$OUTPUT_DIR/logs"
    CHECKPOINT_FILE="$OUTPUT_DIR/.recon_checkpoint"

    # Create directory structure (v3 expanded)
    mkdir -p "$OUTPUT_DIR"/{subdomains,urls,js/files,js/sourcemaps,endpoints,params,logs}
    mkdir -p "$OUTPUT_DIR"/{ports,tech,screenshots,fuzzing,takeover,vulns,cloud,secrets,oob}

    # Handle checkpoint
    if [[ "$FRESH_RUN" == "true" ]]; then
        clear_checkpoint
        log_info "Fresh run — checkpoint cleared"
    elif [[ -f "$CHECKPOINT_FILE" ]]; then
        log_info "Resuming from checkpoint — completed stages: $(paste -sd', ' "$CHECKPOINT_FILE")"
    fi

    # Initialize log
    echo "═══ Recon started: $(date '+%d-%m-%Y %H:%M:%S') ═══" > "$LOG_DIR/recon.log"
    echo "Target: ${DOMAIN:-$TARGET_FILE}" >> "$LOG_DIR/recon.log"
    echo "Mode: $MODE" >> "$LOG_DIR/recon.log"
    touch "$LOG_DIR/errors.log" "$LOG_DIR/install.log"

    log_info "Target: ${DOMAIN:-$TARGET_FILE}"
    log_info "Mode: $MODE"
    log_info "Output: $OUTPUT_DIR"
    log_info "Features: ports=$ENABLE_PORTS fuzz=$ENABLE_FUZZ deep-js=$ENABLE_DEEP_JS takeover=$ENABLE_TAKEOVER cors=$ENABLE_CORS cloud=$ENABLE_CLOUD github=$ENABLE_GITHUB screenshots=$ENABLE_SCREENSHOTS stealth=$ENABLE_STEALTH"
    [[ -n "$DISCORD_WEBHOOK" ]] && log_info "Discord notifications: enabled" || log_info "Discord notifications: disabled"

    # Disk space check
    local free_mb
    free_mb=$(df -m "$OUTPUT_DIR" 2>/dev/null | awk 'NR==2 {print $4}')
    if [[ -n "$free_mb" ]] && [[ "$free_mb" -lt 500 ]]; then
        log_warn "Low disk space: ${free_mb}MB free — may cause issues"
    fi

    # Discord: recon started
    discord_notify "🚀 Recon v3 started (mode: $MODE)"

    # ─── Stage 0: Install tools ───
    if [[ "$SKIP_INSTALL" != "true" ]]; then
        install_all_tools
    else
        log_info "Skipping tool installation (--skip-install)"
    fi

    # Always ensure PATH and verify tools (even with --skip-install)
    export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin"
    verify_tools

    # ─── Stage 1: Subdomains ───
    if [[ "$NO_SUBS" == "true" ]] && [[ "$MODE" == "list" ]]; then
        log_stage "Subdomain Enumeration (SKIPPED — no-subs mode)"
        CURRENT_STAGE=$((CURRENT_STAGE - 1))  # stage counter was incremented by log_stage
        log_info "Using explicit targets from: $TARGET_FILE"
        # Copy targets directly as the subdomain list (strip empty lines)
        sed '/^$/d' "$TARGET_FILE" | sort -u > "$OUTPUT_DIR/subdomains/all.txt"
        local count
        count=$(wc -l < "$OUTPUT_DIR/subdomains/all.txt" 2>/dev/null || echo "0")
        log_success "Loaded $count explicit targets (subdomain enumeration skipped)"
        discord_notify "⏭ Subdomain enumeration skipped — $count explicit targets loaded"
        save_checkpoint "stage_subdomains"
    else
        check_checkpoint "stage_subdomains" || stage_subdomains
    fi

    # ─── Stage 2: DNS Resolution + Permutation ───
    check_checkpoint "stage_dns_resolution" || stage_dns_resolution

    # ─── Stage 3: Live hosts ───
    check_checkpoint "stage_livehost" || stage_livehost

    # ─── Stage 4: Port scanning (optional) ───
    check_checkpoint "stage_ports" || stage_ports

    # ─── Stage 5: Tech fingerprinting ───
    check_checkpoint "stage_tech_detect" || stage_tech_detect

    # ─── Stage 6: Screenshots ───
    check_checkpoint "stage_screenshots" || stage_screenshots

    # ─── Stage 7: URL collection ───
    check_checkpoint "stage_urls" || stage_urls

    # ─── Stage 8: Content fuzzing (optional) ───
    check_checkpoint "stage_fuzzing" || stage_fuzzing

    # ─── Stage 9: JS analysis ───
    check_checkpoint "stage_js_analysis" || stage_js_analysis

    # ─── Stage 10: Parameter discovery ───
    check_checkpoint "stage_params" || stage_params

    # ─── Stage 11: Pattern matching ───
    check_checkpoint "stage_patterns" || stage_patterns

    # ─── Stage 12: Subdomain takeover ───
    check_checkpoint "stage_takeover" || stage_takeover

    # ─── Stage 13: CORS scanning ───
    check_checkpoint "stage_cors" || stage_cors

    # ─── Stage 14: Cloud enumeration (optional) ───
    check_checkpoint "stage_cloud" || stage_cloud

    # ─── Stage 15: GitHub dorking (optional) ───
    check_checkpoint "stage_github" || stage_github

    # ─── Stage 16: Nuclei (optional) ───
    check_checkpoint "stage_nuclei" || stage_nuclei

    # ─── Stage 17: OOB testing ───
    check_checkpoint "stage_oob" || stage_oob

    # ─── Stage 18: Cleanup ───
    check_checkpoint "stage_cleanup" || stage_cleanup

    # ─── Stage 19: Summary ───
    stage_summary

    # All stages completed successfully — clear checkpoint
    clear_checkpoint

    log_success "All stages complete! Results saved to: $OUTPUT_DIR"
}

# Run
main "$@"
