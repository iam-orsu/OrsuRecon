#!/bin/bash
# ============================================================
#  recon.sh — Elite Bug Bounty Recon Automation v2
#  Author: Vamsi | Generated: 2026-03-04
#  Tested on: WSL Kali Linux, Native Kali Linux
# ============================================================

set -o pipefail

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
TOTAL_STAGES=8
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
/_/ |_|\___/\___/\____/_/ /_(_)_/ /_/ v2.0
                                      
   Elite Bug Bounty Recon Automation
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
    local start_time
    start_time=$(date +%s)

    log_info "Running: $tool_name"

    # Run in background + wait so Ctrl+C trap can fire immediately
    bash -c "timeout $STAGE_TIMEOUT $*" >> "$LOG_DIR/recon.log" 2>> "$LOG_DIR/errors.log" &
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

    # Go tools
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

    # Python tools — ParamSpider must be git-cloned (not on PyPI)
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

    # Git-cloned tools
    install_git_tool "LinkFinder"   "https://github.com/GerbenJavado/LinkFinder.git"
    install_git_tool "SecretFinder" "https://github.com/m4ll0k/SecretFinder.git"

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
    for tool_name in "LinkFinder" "SecretFinder"; do
        if [[ ! -d "$TOOLS_DIR/$tool_name" ]]; then
            log_warn "$tool_name not found — will be unavailable"
        fi
    done

    # Check paramspider separately (installed via git clone + pip)
    if ! command -v paramspider &>/dev/null; then
        log_warn "paramspider not found — parameter discovery will be limited"
    fi

    if [[ $missing -eq 0 ]]; then
        log_success "All tools verified and available ✓"
    else
        log_info "Missing: $missing | Auto-installed: $installed | Still missing: $((missing - installed))"
    fi
}

# ─── STAGE 1: SUBDOMAIN ENUMERATION ─────────────────────────
stage_subdomains() {
    log_stage "Subdomain Enumeration"

    local subs_dir="$OUTPUT_DIR/subdomains"
    local raw_file="$subs_dir/raw_subs.txt"
    touch "$raw_file"

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

        # subfinder
        if command -v subfinder &>/dev/null; then
            (
                subfinder -d "$target_domain" -all -silent 2>> "$LOG_DIR/errors.log" >> "$raw_file"
            ) &
            local pid_subfinder=$!
        fi

        # assetfinder
        if command -v assetfinder &>/dev/null; then
            (
                assetfinder --subs-only "$target_domain" 2>> "$LOG_DIR/errors.log" >> "$raw_file"
            ) &
            local pid_assetfinder=$!
        fi

        # crt.sh (curl-based, no tool needed)
        (
            curl -s -m 60 "https://crt.sh/?q=%25.${target_domain}&output=json" 2>> "$LOG_DIR/errors.log" \
                | jq -r '.[].name_value' 2>/dev/null \
                | sed 's/\*\.//g' \
                | sort -u >> "$raw_file"
        ) &
        local pid_crtsh=$!

        # Wait for all parallel jobs for this domain
        [[ -n "${pid_subfinder:-}" ]] && wait "$pid_subfinder" 2>/dev/null
        [[ -n "${pid_assetfinder:-}" ]] && wait "$pid_assetfinder" 2>/dev/null
        wait "$pid_crtsh" 2>/dev/null

        # Also add the root domain itself
        echo "$target_domain" >> "$raw_file"
    done

    # Dedup and remove 'www.' noise
    sed 's/^www\.//' "$raw_file" | sort -u | grep -v '^$' > "$subs_dir/all.txt"
    rm -f "$raw_file"

    local count
    count=$(wc -l < "$subs_dir/all.txt" 2>/dev/null || echo "0")
    log_success "Subdomain enumeration complete: $count unique subdomains across ${#domains[@]} domain(s)"

    discord_notify_results "Subdomain Enumeration" "$count"
    save_checkpoint "stage_subdomains"
}

# ─── STAGE 2: LIVE HOST PROBING ─────────────────────────────
stage_livehost() {
    log_stage "Live Host Probing"

    local subs_file="$OUTPUT_DIR/subdomains/all.txt"
    local subs_dir="$OUTPUT_DIR/subdomains"

    if [[ ! -s "$subs_file" ]]; then
        log_error "No subdomains found — skipping live host probing"
        discord_notify_error "Live Host Probing (no input)"
        return 1
    fi

    if ! command -v httpx &>/dev/null; then
        log_error "httpx not available — skipping"
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


# ─── STAGE 3: URL COLLECTION ────────────────────────────────
stage_urls() {
    log_stage "URL & Endpoint Collection"

    local live_hosts="$OUTPUT_DIR/subdomains/live_hosts.txt"
    local urls_dir="$OUTPUT_DIR/urls"
    local raw_file="$urls_dir/raw_urls.txt"
    touch "$raw_file"

    if [[ ! -s "$live_hosts" ]]; then
        log_warn "No live hosts — skipping URL collection"
        touch "$urls_dir/all_urls.txt" "$urls_dir/inscope_urls.txt"
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

    # katana — active crawling (accepts full URLs, uses live_hosts directly)
    if command -v katana &>/dev/null; then
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

    # hakrawler (accepts full URLs via stdin)
    if command -v hakrawler &>/dev/null; then
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
    else
        # For list mode, keep all URLs (user controls scope)
        cp "$urls_dir/all_urls.txt" "$urls_dir/inscope_urls.txt"
    fi

    local count
    count=$(wc -l < "$urls_dir/inscope_urls.txt" 2>/dev/null || echo "0")
    log_success "URL collection complete: $count in-scope URLs"

    discord_notify_results "URL Collection" "$count"
    save_checkpoint "stage_urls"
}

# ─── STAGE 4: JAVASCRIPT ANALYSIS ───────────────────────────
stage_js_analysis() {
    log_stage "JavaScript File Extraction & Analysis"

    local urls_file="$OUTPUT_DIR/urls/inscope_urls.txt"
    local js_dir="$OUTPUT_DIR/js"
    mkdir -p "$js_dir/files"

    if [[ ! -s "$urls_file" ]]; then
        log_warn "No in-scope URLs — skipping JS analysis"
        return 1
    fi

    # Extract JS URLs
    grep -iE '\.js(\?|$)' "$urls_file" 2>/dev/null | sort -u > "$js_dir/js_urls.txt"

    local js_count
    js_count=$(wc -l < "$js_dir/js_urls.txt" 2>/dev/null || echo "0")
    log_info "Found $js_count JS file URLs"

    if [[ "$js_count" -eq 0 ]]; then
        log_warn "No JS files found"
        touch "$js_dir/linkfinder_results.txt" "$js_dir/secrets_found.txt" "$js_dir/grep_extracts.txt"
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

    # LinkFinder — endpoint extraction
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

    # SecretFinder — secrets detection
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

    # Grep-based extraction as fallback/supplement
    log_info "Running grep-based keyword extraction..."
    touch "$js_dir/grep_extracts.txt"
    if [[ -d "$js_dir/files" ]] && compgen -G "$js_dir/files/*.js" >/dev/null 2>&1; then
        # Extract URLs
        grep -rhoP 'https?://[^\s"'\''<>]+' "$js_dir/files/" 2>/dev/null | sort -u >> "$js_dir/grep_extracts.txt"
        # Extract potential secrets
        grep -rhoiE '(api[_-]?key|api[_-]?secret|token|auth[_-]?token|bearer|jwt|access[_-]?key|password|secret[_-]?key|client[_-]?secret)["\s]*[:=]["\s]*[A-Za-z0-9_\-\.]{8,}' \
            "$js_dir/files/" 2>/dev/null | sort -u >> "$js_dir/grep_extracts.txt"
    fi

    local total_endpoints
    total_endpoints=$(cat "$js_dir/linkfinder_results.txt" "$js_dir/grep_extracts.txt" 2>/dev/null | sort -u | wc -l)
    log_success "JS analysis complete: $dl_count files, $total_endpoints endpoints/secrets"

    discord_notify_results "JS Discovery" "$dl_count files, $total_endpoints endpoints"
    save_checkpoint "stage_js_analysis"
}

# ─── STAGE 5: PARAMETER DISCOVERY ───────────────────────────
stage_params() {
    log_stage "Parameter Discovery"

    local urls_file="$OUTPUT_DIR/urls/inscope_urls.txt"
    local endpoints_dir="$OUTPUT_DIR/endpoints"

    touch "$endpoints_dir/all_endpoints.txt" "$endpoints_dir/paramspider_out.txt"

    if [[ ! -s "$urls_file" ]]; then
        log_warn "No in-scope URLs — skipping parameter discovery"
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
        "$endpoints_dir/paramspider_out.txt" \
        2>/dev/null | sort -u > "$endpoints_dir/all_endpoints.txt"

    local count
    count=$(wc -l < "$endpoints_dir/all_endpoints.txt" 2>/dev/null || echo "0")
    log_success "Endpoint discovery complete: $count total endpoints"

    discord_notify_results "Endpoint Discovery" "$count"
    save_checkpoint "stage_params"
}

# ─── STAGE 6: GF PATTERN MATCHING ───────────────────────────
stage_patterns() {
    log_stage "Pattern-Based Vulnerability Fingerprinting"

    local urls_file="$OUTPUT_DIR/urls/inscope_urls.txt"
    local params_dir="$OUTPUT_DIR/params"

    if [[ ! -s "$urls_file" ]]; then
        log_warn "No in-scope URLs — skipping gf patterns"
        return 1
    fi

    if ! command -v gf &>/dev/null; then
        log_warn "gf not available — skipping pattern matching"
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

# ─── STAGE 7: NUCLEI SCAN (OPTIONAL) ────────────────────────
stage_nuclei() {
    log_stage "Nuclei Vulnerability Scan"

    if [[ "$ENABLE_NUCLEI" != "true" ]]; then
        log_info "Nuclei scanning disabled — use -n flag to enable"
        return 0
    fi

    local live_hosts="$OUTPUT_DIR/subdomains/live_hosts.txt"

    if [[ ! -s "$live_hosts" ]]; then
        log_warn "No live hosts — skipping nuclei scan"
        return 1
    fi

    if ! command -v nuclei &>/dev/null; then
        log_error "nuclei not available — skipping"
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

# ─── STAGE 8: SUMMARY ───────────────────────────────────────
stage_summary() {
    log_stage "Generating Summary"

    local end_time
    end_time=$(date +%s)
    local elapsed=$(( end_time - SCRIPT_START ))
    local duration
    duration="$(( elapsed / 60 ))m $(( elapsed % 60 ))s"

    # Count results
    local subs live urls jsfiles endpoints params
    subs=$(wc -l < "$OUTPUT_DIR/subdomains/all.txt" 2>/dev/null || echo "0")
    live=$(wc -l < "$OUTPUT_DIR/subdomains/live_hosts.txt" 2>/dev/null || echo "0")
    urls=$(wc -l < "$OUTPUT_DIR/urls/inscope_urls.txt" 2>/dev/null || echo "0")
    jsfiles=$(wc -l < "$OUTPUT_DIR/js/js_urls.txt" 2>/dev/null || echo "0")
    endpoints=$(wc -l < "$OUTPUT_DIR/endpoints/all_endpoints.txt" 2>/dev/null || echo "0")
    params=$(cat "$OUTPUT_DIR/params/"*.txt 2>/dev/null | sort -u | wc -l || echo "0")

    local failed_str="None"
    if [[ ${#FAILED_STAGES[@]} -gt 0 ]]; then
        failed_str=$(IFS=', '; echo "${FAILED_STAGES[*]}")
    fi

    # Write summary file
    cat > "$LOG_DIR/summary.txt" << EOFSUMMARY
═══════════════════════════════════════════════════
  RECON SUMMARY — $(date '+%d-%m-%Y %H:%M:%S')
═══════════════════════════════════════════════════

  Target:          ${DOMAIN:-$TARGET_FILE}
  Mode:            $MODE
  Duration:        $duration
  Host:            $(hostname 2>/dev/null || echo "unknown")

  ─────────────────────────────────────────────────
  RESULTS
  ─────────────────────────────────────────────────

  Subdomains:      $subs
  Live Hosts:      $live
  URLs:            $urls
  JS Files:        $jsfiles
  Endpoints:       $endpoints
  Parameters:      $params

  ─────────────────────────────────────────────────
  STATUS
  ─────────────────────────────────────────────────

  Failed Stages:   $failed_str

  ─────────────────────────────────────────────────
  OUTPUT DIRECTORY
  ─────────────────────────────────────────────────

  $OUTPUT_DIR/

═══════════════════════════════════════════════════
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
    echo "  -l, --list <file>    Process a list of subdomains/domains"
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo "  -o, --output <dir>   Output directory (default: ./recon-output)"
    echo "  -n, --nuclei         Enable nuclei vulnerability scanning"
    echo "  -s, --skip-install   Skip tool installation checks"
    echo "  --timeout <sec>      Per-stage timeout in seconds (default: 300)"
    echo "  --threads <n>        Thread count for tools (default: 5)"
    echo "  --fresh              Ignore checkpoint — restart from scratch"
    echo "  --rate-delay <sec>   Delay between API-heavy tools (default: 5)"
    echo "  -h, --help           Show this help message"
    echo ""
    echo -e "${BOLD}Environment:${NC}"
    echo "  DISCORD_WEBHOOK      Discord webhook URL for notifications"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  ./recon.sh forexfactory.com"
    echo "  ./recon.sh -l targets.txt --nuclei"
    echo "  DISCORD_WEBHOOK=\"https://discord.com/api/...\" ./recon.sh example.com"
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
                MODE="list"
                TARGET_FILE="$2"
                if [[ -z "$TARGET_FILE" ]] || [[ ! -f "$TARGET_FILE" ]]; then
                    echo -e "${RED}[✗] Error: List file '$TARGET_FILE' not found${NC}"
                    exit 1
                fi
                shift 2
                ;;
            -o|--output)
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
            --timeout)
                STAGE_TIMEOUT="$2"
                shift 2
                ;;
            --fresh)
                FRESH_RUN=true
                shift
                ;;
            --rate-delay)
                RATE_LIMIT_DELAY="$2"
                shift 2
                ;;
            --threads)
                THREADS="$2"
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

    # Set up output directory
    if [[ "$MODE" == "domain" ]]; then
        OUTPUT_DIR="${OUTPUT_DIR}/${DOMAIN}"
    fi

    # Convert to absolute path so cd in subshells doesn't break log paths
    OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"
    LOG_DIR="$OUTPUT_DIR/logs"
    CHECKPOINT_FILE="$OUTPUT_DIR/.recon_checkpoint"

    # Create directory structure
    mkdir -p "$OUTPUT_DIR"/{subdomains,urls,js/files,endpoints,params,logs}

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
    [[ -n "$DISCORD_WEBHOOK" ]] && log_info "Discord notifications: enabled" || log_info "Discord notifications: disabled"

    # Disk space check
    local free_mb
    free_mb=$(df -m "$OUTPUT_DIR" 2>/dev/null | awk 'NR==2 {print $4}')
    if [[ -n "$free_mb" ]] && [[ "$free_mb" -lt 500 ]]; then
        log_warn "Low disk space: ${free_mb}MB free — may cause issues"
    fi

    # Discord: recon started
    discord_notify "🚀 Recon started (mode: $MODE)"

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
    check_checkpoint "stage_subdomains" || stage_subdomains

    # ─── Stage 2: Live hosts ───
    check_checkpoint "stage_livehost" || stage_livehost

    # ─── Stage 3: URL collection ───
    check_checkpoint "stage_urls" || stage_urls

    # ─── Stage 4: JS analysis ───
    check_checkpoint "stage_js_analysis" || stage_js_analysis

    # ─── Stage 5: Parameter discovery ───
    check_checkpoint "stage_params" || stage_params

    # ─── Stage 6: Pattern matching ───
    check_checkpoint "stage_patterns" || stage_patterns

    # ─── Stage 7: Nuclei (optional) ───
    check_checkpoint "stage_nuclei" || stage_nuclei

    # ─── Stage 8: Summary ───
    stage_summary

    # All stages completed successfully — clear checkpoint
    clear_checkpoint

    log_success "All stages complete! Results saved to: $OUTPUT_DIR"
}

# Run
main "$@"
