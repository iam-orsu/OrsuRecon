#!/bin/bash
#
#  ██████╗ ██████╗ ███████╗██╗   ██╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
# ██╔═══██╗██╔══██╗██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
# ██║   ██║██████╔╝███████╗██║   ██║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
# ██║   ██║██╔══██╗╚════██║██║   ██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
# ╚██████╔╝██║  ██║███████║╚██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
#  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
#
# Production-grade Bug Bounty Recon Framework
# Compatible with Kali Linux, WSL, and VPS environments
# 
# Usage: ./recon.sh <domain> [options]
#
# Options:
#   --install    Install all dependencies
#   --check      Run preflight checks only
#   --help       Show this help message
#

set -o pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Timeouts (seconds)
TIMEOUT_SUBDOMAIN=600
TIMEOUT_HTTPX=300
TIMEOUT_SCREENSHOT=600
TIMEOUT_CRAWL=600
TIMEOUT_GAU=300

# Rate limits
RATE_HTTPX=50
RATE_SCREENSHOT=2
RATE_CRAWL=10

# Batch sizes
BATCH_SIZE=100

# System packages
SYSTEM_PACKAGES=(
    "golang-go"
    "git"
    "jq"
    "chromium"
    "unzip"
)

# Go tools registry (amass removed - too slow and noisy)
declare -A GO_TOOLS=(
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["gowitness"]="github.com/sensepost/gowitness@latest"
    ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
    ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
    ["unfurl"]="github.com/tomnomnom/unfurl@latest"
)

# Environment detection
detect_environment() {
    if [[ -n "$WSL_DISTRO_NAME" ]] || grep -qi microsoft /proc/version 2>/dev/null; then
        ENVIRONMENT="wsl"
    elif [[ -f /sys/hypervisor/uuid ]] || [[ -d /sys/class/dmi ]] && grep -qiE 'amazon|google|digitalocean|vultr|linode' /sys/class/dmi/id/product_name 2>/dev/null; then
        ENVIRONMENT="vps"
    else
        ENVIRONMENT="native"
    fi
    export ENVIRONMENT
}

# Tracking params to filter out
TRACKING_PARAMS=(
    "utm_source" "utm_medium" "utm_campaign" "utm_term" "utm_content"
    "fbclid" "gclid" "gclsrc" "dclid" "_ga" "_gid" "mc_eid" "mc_cid"
    "msclkid" "yclid" "ref" "source" "affiliate" "partner"
    "trk" "tracking" "track" "campaign" "ad" "adgroup"
)

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

log_info() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[INFO]${NC} $1"
    [[ -n "$LOG_DIR" ]] && echo "[$timestamp] [INFO] $1" >> "$LOG_DIR/recon.log"
}

log_success() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[✓]${NC} $1"
    [[ -n "$LOG_DIR" ]] && echo "[$timestamp] [SUCCESS] $1" >> "$LOG_DIR/recon.log"
}

log_warn() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[!]${NC} $1"
    [[ -n "$LOG_DIR" ]] && echo "[$timestamp] [WARN] $1" >> "$LOG_DIR/recon.log"
}

log_error() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[✗]${NC} $1" >&2
    [[ -n "$LOG_DIR" ]] && echo "[$timestamp] [ERROR] $1" >> "$LOG_DIR/recon.log"
}

log_header() {
    echo ""
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${MAGENTA}  $1${NC}"
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

with_timeout() {
    local seconds="$1"
    shift
    timeout --kill-after=10 "$seconds" "$@"
    local exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
        log_warn "Command timed out after ${seconds}s"
    fi
    return $exit_code
}

validate_domain() {
    local input="$1"
    
    # Strip protocol
    input="${input#http://}"
    input="${input#https://}"
    
    # Strip trailing slash and path
    input="${input%%/*}"
    
    # Strip wildcard prefix
    input="${input#\*.}"
    
    # Basic validation
    if [[ -z "$input" ]]; then
        log_error "Empty domain provided"
        return 1
    fi
    
    if [[ ! "$input" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]]; then
        log_error "Invalid domain format: $input"
        return 1
    fi
    
    echo "$input"
    return 0
}

validate_output() {
    local file="$1"
    local min_lines="${2:-1}"
    
    if [[ ! -f "$file" ]]; then
        log_warn "Output file not created: $file"
        return 1
    fi
    
    local line_count
    line_count=$(wc -l < "$file" 2>/dev/null || echo 0)
    
    if [[ "$line_count" -lt "$min_lines" ]]; then
        log_warn "Output file has fewer than $min_lines lines: $file ($line_count lines)"
        return 1
    fi
    
    log_info "Output validated: $file ($line_count lines)"
    return 0
}

create_empty_marker() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        touch "$file"
    fi
}

get_chromium_binary() {
    if command -v chromium &>/dev/null; then
        echo "chromium"
    elif command -v chromium-browser &>/dev/null; then
        echo "chromium-browser"
    elif command -v google-chrome &>/dev/null; then
        echo "google-chrome"
    else
        echo ""
    fi
}

# ============================================================================
# GO ENVIRONMENT SETUP
# ============================================================================

setup_go_env() {
    export GOPATH="${GOPATH:-$HOME/go}"
    mkdir -p "$GOPATH/bin"
    
    if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
        export PATH="$PATH:$GOPATH/bin"
    fi
    
    if ! command -v go &>/dev/null; then
        log_error "Go not found. Install with: sudo apt install golang-go"
        return 1
    fi
    
    local go_version
    go_version=$(go version 2>/dev/null | awk '{print $3}')
    log_info "Go version: $go_version"
    log_info "GOPATH: $GOPATH"
    
    return 0
}

persist_go_path() {
    local shell_rc="$HOME/.bashrc"
    local path_line='export PATH="$PATH:$HOME/go/bin"'
    
    if ! grep -qF 'go/bin' "$shell_rc" 2>/dev/null; then
        echo "" >> "$shell_rc"
        echo "# Go binaries (added by recon.sh)" >> "$shell_rc"
        echo "$path_line" >> "$shell_rc"
        log_info "Added Go PATH to $shell_rc"
    fi
}

# ============================================================================
# DEPENDENCY INSTALLATION
# ============================================================================

install_system_deps() {
    log_header "Installing System Dependencies"
    
    local missing=()
    
    for pkg in "${SYSTEM_PACKAGES[@]}"; do
        if ! dpkg -s "$pkg" &>/dev/null; then
            # Check for chromium-browser variant
            if [[ "$pkg" == "chromium" ]] && dpkg -s "chromium-browser" &>/dev/null; then
                continue
            fi
            missing+=("$pkg")
        fi
    done
    
    if [[ ${#missing[@]} -eq 0 ]]; then
        log_success "All system packages already installed"
        return 0
    fi
    
    log_info "Installing missing packages: ${missing[*]}"
    
    if ! sudo apt-get update -qq 2>&1; then
        log_error "apt-get update failed"
        return 1
    fi
    
    for pkg in "${missing[@]}"; do
        log_info "Installing $pkg..."
        if ! sudo apt-get install -y -qq "$pkg" 2>&1; then
            # Try chromium-browser if chromium fails
            if [[ "$pkg" == "chromium" ]]; then
                if sudo apt-get install -y -qq "chromium-browser" 2>&1; then
                    log_success "Installed chromium-browser (alternative)"
                    continue
                fi
            fi
            log_error "Failed to install: $pkg"
        else
            log_success "Installed $pkg"
        fi
    done
    
    return 0
}

install_go_tool() {
    local tool_name="$1"
    local tool_path="${GO_TOOLS[$tool_name]}"
    
    if [[ -z "$tool_path" ]]; then
        log_error "Unknown tool: $tool_name"
        return 1
    fi
    
    if command -v "$tool_name" &>/dev/null; then
        log_success "$tool_name already installed"
        return 0
    fi
    
    log_info "Installing $tool_name... (this may take a few minutes)"
    
    if timeout 300 go install -v "$tool_path" 2>&1 | tail -3; then
        if command -v "$tool_name" &>/dev/null; then
            log_success "$tool_name installed successfully"
            return 0
        else
            log_error "$tool_name binary not found after install"
            return 1
        fi
    else
        log_error "Failed to install $tool_name (timeout or error)"
        return 1
    fi
}

install_all_go_tools() {
    log_header "Installing Go Tools"
    
    local failed=()
    
    for tool in "${!GO_TOOLS[@]}"; do
        if ! install_go_tool "$tool"; then
            failed+=("$tool")
        fi
    done
    
    if [[ ${#failed[@]} -gt 0 ]]; then
        log_warn "Failed to install: ${failed[*]}"
        log_warn "Script will skip modules requiring these tools"
    fi
    
    # Symlink Go binaries to /usr/bin for global access
    symlink_go_tools
    
    return 0
}

symlink_go_tools() {
    log_info "Ensuring all Go tools are globally accessible..."
    
    # Get real user's home when running with sudo
    local real_home
    if [[ -n "$SUDO_USER" ]]; then
        real_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    else
        real_home="$HOME"
    fi
    
    local user_go_bin="$real_home/go/bin"
    local root_go_bin="/root/go/bin"
    
    for tool in "${!GO_TOOLS[@]}"; do
        # Step 1: Check if tool already works (installed via apt or already in PATH)
        if command -v "$tool" &>/dev/null; then
            local current_path
            current_path=$(command -v "$tool")
            log_info "$tool OK at $current_path"
            continue
        fi
        
        # Step 2: Tool not in PATH, check user's ~/go/bin
        if [[ -f "$user_go_bin/$tool" ]]; then
            log_info "Found $tool in $user_go_bin, linking to /usr/bin..."
            sudo rm -f "/usr/bin/$tool" 2>/dev/null
            if sudo ln -sf "$user_go_bin/$tool" "/usr/bin/$tool"; then
                log_success "Linked $tool -> /usr/bin/$tool"
            else
                log_warn "Failed to link $tool"
            fi
            continue
        fi
        
        # Step 3: Check root's ~/go/bin (if installed with sudo)
        if [[ -f "$root_go_bin/$tool" ]]; then
            log_info "Found $tool in $root_go_bin, linking to /usr/bin..."
            sudo rm -f "/usr/bin/$tool" 2>/dev/null
            if sudo ln -sf "$root_go_bin/$tool" "/usr/bin/$tool"; then
                log_success "Linked $tool -> /usr/bin/$tool"
            else
                log_warn "Failed to link $tool"
            fi
            continue
        fi
        
        # Step 4: Tool not found anywhere
        log_warn "$tool not found anywhere - will be installed"
    done
}

validate_chromium() {
    local chrome_bin
    chrome_bin=$(get_chromium_binary)
    
    if [[ -z "$chrome_bin" ]]; then
        log_error "Chromium not found"
        return 1
    fi
    
    log_info "Testing Chromium headless mode..."
    if "$chrome_bin" --headless --disable-gpu --no-sandbox \
        --dump-dom "about:blank" &>/dev/null; then
        log_success "Chromium headless mode works"
    else
        log_warn "Chromium headless test failed (screenshots may not work)"
    fi
    
    return 0
}

install_dependencies() {
    log_header "Dependency Installation"
    
    if ! setup_go_env; then
        log_error "Go environment setup failed"
        return 1
    fi
    
    if ! install_system_deps; then
        log_warn "Some system packages failed to install"
    fi
    
    install_all_go_tools
    
    validate_chromium || true
    
    persist_go_path
    
    check_tool_availability
    
    log_success "Dependency installation complete"
    return 0
}

# ============================================================================
# PREFLIGHT CHECK
# ============================================================================

check_tool_availability() {
    echo ""
    echo "┌─────────────┬────────────┬─────────────────────────────────────────┐"
    echo "│ Tool        │ Status     │ Path                                    │"
    echo "├─────────────┼────────────┼─────────────────────────────────────────┤"
    
    for tool in subfinder httpx gowitness gau katana unfurl; do
        local status="❌ Missing"
        local path="-"
        
        if command -v "$tool" &>/dev/null; then
            status="✅ OK"
            path=$(command -v "$tool")
            # Truncate path if too long
            if [[ ${#path} -gt 39 ]]; then
                path="...${path: -36}"
            fi
        fi
        
        printf "│ %-11s │ %-10s │ %-39s │\n" "$tool" "$status" "$path"
    done
    
    echo "└─────────────┴────────────┴─────────────────────────────────────────┘"
    echo ""
}

run_preflight_check() {
    echo ""
    echo "========================================"
    echo "  RECON FRAMEWORK PREFLIGHT CHECK"
    echo "========================================"
    echo ""
    
    local errors=0
    
    echo "[1/4] Go Runtime"
    if command -v go &>/dev/null; then
        echo "  ✅ $(go version)"
    else
        echo "  ❌ Go not installed"
        ((errors++))
    fi
    
    echo ""
    echo "[2/4] System Packages"
    for pkg in git jq; do
        if dpkg -s "$pkg" &>/dev/null 2>&1; then
            echo "  ✅ $pkg"
        else
            echo "  ❌ $pkg missing"
            ((errors++))
        fi
    done
    
    local chrome_bin
    chrome_bin=$(get_chromium_binary)
    if [[ -n "$chrome_bin" ]]; then
        echo "  ✅ chromium ($chrome_bin)"
    else
        echo "  ❌ chromium missing"
        ((errors++))
    fi
    
    echo ""
    echo "[3/4] Go Tools"
    check_tool_availability
    
    echo "[4/4] Chromium Headless (WSL)"
    if [[ -n "$chrome_bin" ]]; then
        if "$chrome_bin" --headless --disable-gpu --no-sandbox \
            --dump-dom "about:blank" &>/dev/null; then
            echo "  ✅ Headless mode works"
        else
            echo "  ⚠️ Headless mode may have issues"
        fi
    else
        echo "  ❌ Chromium not found"
        ((errors++))
    fi
    
    echo ""
    if [[ $errors -eq 0 ]]; then
        echo "✅ All critical preflight checks passed"
        return 0
    else
        echo "❌ $errors preflight check(s) failed"
        return 1
    fi
}

# ============================================================================
# DIRECTORY SETUP
# ============================================================================

setup_directories() {
    local base_dir="$1"
    
    local dirs=(
        "subdomains"
        "live"
        "screenshots"
        "js"
        "urls"
        "params"
        "interesting"
        "logs"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$base_dir/$dir"
    done
    
    SUBDOMAINS_DIR="$base_dir/subdomains"
    LIVE_DIR="$base_dir/live"
    SCREENSHOTS_DIR="$base_dir/screenshots"
    JS_DIR="$base_dir/js"
    URLS_DIR="$base_dir/urls"
    PARAMS_DIR="$base_dir/params"
    INTERESTING_DIR="$base_dir/interesting"
    LOG_DIR="$base_dir/logs"
    
    echo "=== Recon started at $(date) ===" > "$LOG_DIR/recon.log"
    echo "=== Domain: $DOMAIN ===" >> "$LOG_DIR/recon.log"
    : > "$LOG_DIR/module_status.log"
    
    log_success "Directory structure created: $base_dir"
}

# ============================================================================
# MODULE WRAPPER
# ============================================================================

run_module() {
    local module_name="$1"
    local module_func="$2"
    local required_tool="$3"
    
    log_header "$module_name"
    
    if [[ -n "$required_tool" ]] && ! command -v "$required_tool" &>/dev/null; then
        log_warn "Skipping $module_name: $required_tool not found"
        echo "$module_name: SKIPPED (missing $required_tool)" >> "$LOG_DIR/module_status.log"
        return 0
    fi
    
    local start_time
    start_time=$(date +%s)
    
    if $module_func 2>&1 | tee -a "$LOG_DIR/recon.log"; then
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        log_success "$module_name completed in ${duration}s"
        echo "$module_name: SUCCESS (${duration}s)" >> "$LOG_DIR/module_status.log"
    else
        log_error "$module_name failed"
        echo "$module_name: FAILED" >> "$LOG_DIR/module_status.log"
    fi
    
    return 0
}

# ============================================================================
# RECON MODULES
# ============================================================================

mod_subdomain_enum() {
    log_info "Starting subdomain enumeration for $DOMAIN"
    
    local subfinder_out="$SUBDOMAINS_DIR/subfinder.txt"
    local all_out="$SUBDOMAINS_DIR/all_subdomains.txt"
    
    # Subfinder - primary subdomain enumeration tool
    if command -v subfinder &>/dev/null; then
        log_info "Running subfinder..."
        if with_timeout "$TIMEOUT_SUBDOMAIN" subfinder -d "$DOMAIN" -silent -all -o "$subfinder_out" 2>/dev/null; then
            if [[ -f "$subfinder_out" ]]; then
                log_success "Subfinder found $(wc -l < "$subfinder_out") subdomains"
            fi
        else
            log_warn "Subfinder failed or timed out"
            create_empty_marker "$subfinder_out"
        fi
    else
        log_error "subfinder not found - cannot enumerate subdomains"
        return 1
    fi
    
    # Deduplicate and filter to valid subdomains of target
    log_info "Normalizing and deduplicating subdomains..."
    cat "$SUBDOMAINS_DIR"/*.txt 2>/dev/null | \
        tr '[:upper:]' '[:lower:]' | \
        sed 's/^\*\.//' | \
        grep -E '^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$' | \
        grep -iE "(^|\.)${DOMAIN//./\\.}$" | \
        sort -u > "$all_out"
    
    local total
    total=$(wc -l < "$all_out" 2>/dev/null || echo 0)
    log_success "Total unique subdomains: $total"
    log_info "Saved to: $all_out"
    
    if [[ "$total" -eq 0 ]]; then
        log_error "No subdomains found"
        return 1
    fi
    
    return 0
}

mod_live_detection() {
    local input="$SUBDOMAINS_DIR/all_subdomains.txt"
    local output="$LIVE_DIR/live.txt"
    local output_json="$LIVE_DIR/live.json"
    
    if [[ ! -s "$input" ]]; then
        log_error "No subdomains to probe (missing: $input)"
        return 1
    fi
    
    local count
    count=$(wc -l < "$input")
    log_info "Probing $count subdomains for live HTTP/HTTPS hosts..."
    
    # httpx with follow-redirects, status code filtering
    if with_timeout "$TIMEOUT_HTTPX" httpx -l "$input" \
        -silent \
        -threads "$RATE_HTTPX" \
        -timeout 10 \
        -retries 1 \
        -follow-redirects \
        -o "$output" \
        2>/dev/null; then
        
        if [[ -f "$output" ]] && [[ -s "$output" ]]; then
            local live_count
            live_count=$(wc -l < "$output")
            log_success "Found $live_count live hosts"
            log_info "Saved to: $output"
            
            # Collect JSON details for the live hosts
            log_info "Collecting detailed host info..."
            httpx -l "$output" -silent -json -o "$output_json" 2>/dev/null || true
        fi
    else
        log_warn "httpx failed or timed out"
    fi
    
    create_empty_marker "$output"
    
    if [[ ! -s "$output" ]]; then
        log_warn "No live hosts detected - downstream modules will be skipped"
        return 1
    fi
    
    return 0
}

mod_screenshot() {
    local input="$LIVE_DIR/live.txt"
    local output_dir="$SCREENSHOTS_DIR"
    
    if [[ ! -s "$input" ]]; then
        log_warn "Skipping screenshots: no live hosts in $input"
        return 0
    fi
    
    local count
    count=$(wc -l < "$input")
    log_info "Taking screenshots of $count live hosts..."
    
    local chrome_bin
    chrome_bin=$(get_chromium_binary)
    
    # gowitness v3 uses 'scan file' command
    if with_timeout "$TIMEOUT_SCREENSHOT" gowitness scan file \
        -f "$input" \
        -s "$output_dir" \
        --chrome-path "$chrome_bin" \
        -t 4 \
        -T 15 \
        -q \
        2>/dev/null; then
        
        local screenshot_count
        screenshot_count=$(find "$output_dir" -name "*.jpeg" -o -name "*.png" 2>/dev/null | wc -l)
        log_success "Captured $screenshot_count screenshots"
    else
        log_warn "gowitness failed or timed out"
    fi
    
    return 0
}

mod_url_harvest_gau() {
    local input="$LIVE_DIR/live.txt"
    local output="$URLS_DIR/gau.txt"
    
    if [[ ! -s "$input" ]]; then
        log_warn "Skipping gau: no live hosts in $input"
        return 0
    fi
    
    local count
    count=$(wc -l < "$input")
    log_info "Harvesting historical URLs for $count live hosts with gau..."
    
    # Extract hostnames from live URLs and query gau for each
    local temp_hosts="$URLS_DIR/.gau_hosts.tmp"
    sed -E 's|https?://([^/]+).*|\1|' "$input" | sort -u > "$temp_hosts"
    
    # Run gau on each host
    while IFS= read -r host; do
        if with_timeout "$TIMEOUT_GAU" gau --threads 5 "$host" 2>/dev/null; then
            true
        fi
    done < "$temp_hosts" >> "$output"
    
    rm -f "$temp_hosts"
    
    if [[ -f "$output" ]]; then
        sort -u "$output" -o "$output"
        log_success "gau found $(wc -l < "$output") historical URLs"
    fi
    
    create_empty_marker "$output"
    return 0
}

mod_url_harvest_katana() {
    local input="$LIVE_DIR/live.txt"
    local output="$URLS_DIR/katana.txt"
    
    if [[ ! -s "$input" ]]; then
        log_warn "Skipping katana crawl: no live hosts in $input"
        return 0
    fi
    
    log_info "Crawling live hosts with katana..."
    
    local chrome_bin
    chrome_bin=$(get_chromium_binary)
    
    local katana_args=(-list "$input" -silent -o "$output" -jc -d 2 -c "$RATE_CRAWL")
    
    # Add headless browser if available
    if [[ -n "$chrome_bin" ]]; then
        katana_args+=(-headless -system-chrome)
    fi
    
    if with_timeout "$TIMEOUT_CRAWL" katana "${katana_args[@]}" 2>/dev/null; then
        if [[ -f "$output" ]]; then
            log_success "katana found $(wc -l < "$output") URLs"
        fi
    else
        log_warn "katana failed or timed out"
    fi
    
    create_empty_marker "$output"
    return 0
}

mod_url_merge() {
    local output="$URLS_DIR/all.txt"
    
    log_info "Merging all discovered URLs..."
    
    # Combine all URL sources
    cat "$URLS_DIR"/*.txt 2>/dev/null | \
        grep -E "^https?://" | \
        sort -u > "$output"
    
    local total
    total=$(wc -l < "$output" 2>/dev/null || echo 0)
    log_success "Total unique URLs: $total"
    
    return 0
}

mod_js_discovery() {
    local input="$URLS_DIR/all.txt"
    local js_files="$JS_DIR/files.txt"
    local js_endpoints="$JS_DIR/endpoints.txt"
    
    if [[ ! -s "$input" ]]; then
        log_warn "Skipping JS discovery: no URLs collected"
        return 0
    fi
    
    log_info "Extracting JavaScript files and endpoints..."
    
    # Extract .js file URLs
    grep -iE '\.js(\?|$)' "$input" | \
        grep -vE '\.json' | \
        sort -u > "$js_files"
    
    local js_count
    js_count=$(wc -l < "$js_files" 2>/dev/null || echo 0)
    log_success "Found $js_count JavaScript files"
    
    # Extract potential API endpoints from URLs
    grep -iE '(/api/|/v[0-9]+/|/graphql|/rest/|/ajax/|/json/)' "$input" | \
        sort -u > "$js_endpoints"
    
    local endpoint_count
    endpoint_count=$(wc -l < "$js_endpoints" 2>/dev/null || echo 0)
    log_success "Found $endpoint_count API endpoints"
    
    return 0
}

mod_param_extract() {
    local input="$URLS_DIR/all.txt"
    local raw_params="$PARAMS_DIR/raw.txt"
    local unique_params="$PARAMS_DIR/unique.txt"
    local filtered_params="$PARAMS_DIR/filtered.txt"
    
    if [[ ! -s "$input" ]]; then
        log_warn "No URLs to extract parameters from"
        return 0
    fi
    
    log_info "Extracting parameters from URLs..."
    
    # Extract parameters using unfurl
    if command -v unfurl &>/dev/null; then
        unfurl -u keys < "$input" 2>/dev/null | sort -u > "$raw_params"
    else
        # Fallback: basic grep extraction
        grep -oE '[?&]([^=&]+)=' "$input" | \
            sed 's/[?&]//g' | \
            sed 's/=$//g' | \
            sort -u > "$raw_params"
    fi
    
    # Create unique sorted list
    sort -u "$raw_params" > "$unique_params"
    
    # Filter out tracking params
    local tracking_regex
    tracking_regex=$(printf '%s\n' "${TRACKING_PARAMS[@]}" | paste -sd '|')
    
    grep -ivE "^($tracking_regex)$" "$unique_params" > "$filtered_params" 2>/dev/null || true
    
    local param_count
    param_count=$(wc -l < "$filtered_params" 2>/dev/null || echo 0)
    log_success "Found $param_count unique parameters (after filtering)"
    
    return 0
}

mod_interesting_endpoints() {
    local input="$URLS_DIR/all.txt"
    
    if [[ ! -s "$input" ]]; then
        log_warn "No URLs to analyze"
        return 0
    fi
    
    log_info "Detecting interesting endpoints..."
    
    # Auth endpoints
    grep -iE '(login|signin|sign-in|auth|oauth|sso|saml|logout|signout|register|signup|password|reset|forgot|2fa|mfa|otp|token|session|jwt)' "$input" | \
        sort -u > "$INTERESTING_DIR/auth.txt"
    log_info "Auth endpoints: $(wc -l < "$INTERESTING_DIR/auth.txt")"
    
    # Admin endpoints
    grep -iE '(admin|administrator|manager|dashboard|panel|control|console|backend|cms|wp-admin|phpmyadmin)' "$input" | \
        sort -u > "$INTERESTING_DIR/admin.txt"
    log_info "Admin endpoints: $(wc -l < "$INTERESTING_DIR/admin.txt")"
    
    # API endpoints
    grep -iE '(/api/|/v[0-9]+/|/rest/|/graphql|/gql|/swagger|/openapi|/docs/api)' "$input" | \
        sort -u > "$INTERESTING_DIR/api.txt"
    log_info "API endpoints: $(wc -l < "$INTERESTING_DIR/api.txt")"
    
    # Debug/Development endpoints
    grep -iE '(debug|test|dev|staging|stage|uat|sandbox|demo|sample|example|poc|internal|temp|tmp|backup|bak|old|copy)' "$input" | \
        sort -u > "$INTERESTING_DIR/debug.txt"
    log_info "Debug endpoints: $(wc -l < "$INTERESTING_DIR/debug.txt")"
    
    # File/Upload endpoints
    grep -iE '(upload|file|download|attachment|document|import|export|media|image|photo|asset)' "$input" | \
        sort -u > "$INTERESTING_DIR/files.txt"
    log_info "File endpoints: $(wc -l < "$INTERESTING_DIR/files.txt")"
    
    # Config/Sensitive files
    grep -iE '\.(conf|config|cfg|ini|env|yml|yaml|json|xml|bak|backup|log|sql|db|sqlite)(\?|$)' "$input" | \
        sort -u > "$INTERESTING_DIR/config.txt"
    log_info "Config files: $(wc -l < "$INTERESTING_DIR/config.txt")"
    
    return 0
}

# ============================================================================
# SUMMARY GENERATOR
# ============================================================================

generate_summary() {
    local summary_file="$OUTPUT_DIR/summary.txt"
    
    echo "" 
    echo "========================================"
    echo "  RECON SUMMARY: $DOMAIN"
    echo "  Generated: $(date)"
    echo "========================================"
    echo ""
    
    {
        echo "========================================"
        echo "  RECON SUMMARY: $DOMAIN"
        echo "  Generated: $(date)"
        echo "========================================"
        echo ""
    } > "$summary_file"
    
    # Count results
    local subs=0 live=0 urls=0 params=0 js=0
    
    [[ -f "$SUBDOMAINS_DIR/all_subdomains.txt" ]] && subs=$(wc -l < "$SUBDOMAINS_DIR/all_subdomains.txt")
    [[ -f "$LIVE_DIR/live.txt" ]] && live=$(wc -l < "$LIVE_DIR/live.txt")
    [[ -f "$URLS_DIR/all.txt" ]] && urls=$(wc -l < "$URLS_DIR/all.txt")
    [[ -f "$PARAMS_DIR/filtered.txt" ]] && params=$(wc -l < "$PARAMS_DIR/filtered.txt")
    [[ -f "$JS_DIR/files.txt" ]] && js=$(wc -l < "$JS_DIR/files.txt")
    
    echo "📊 Results:"
    echo "   Subdomains discovered: $subs"
    echo "   Live hosts: $live"
    echo "   URLs collected: $urls"
    echo "   Unique parameters: $params"
    echo "   JS files found: $js"
    echo ""
    
    {
        echo "📊 Results:"
        echo "   Subdomains discovered: $subs"
        echo "   Live hosts: $live"
        echo "   URLs collected: $urls"
        echo "   Unique parameters: $params"
        echo "   JS files found: $js"
        echo ""
    } >> "$summary_file"
    
    # Interesting endpoints summary
    echo "🎯 Interesting Endpoints:"
    for f in "$INTERESTING_DIR"/*.txt; do
        if [[ -f "$f" ]]; then
            local name
            name=$(basename "$f" .txt)
            local count
            count=$(wc -l < "$f")
            echo "   $name: $count"
        fi
    done
    echo ""
    
    {
        echo "🎯 Interesting Endpoints:"
        for f in "$INTERESTING_DIR"/*.txt; do
            if [[ -f "$f" ]]; then
                local name
                name=$(basename "$f" .txt)
                local count
                count=$(wc -l < "$f")
                echo "   $name: $count"
            fi
        done
        echo ""
    } >> "$summary_file"
    
    # Module status
    echo "📋 Module Status:"
    cat "$LOG_DIR/module_status.log"
    echo ""
    
    {
        echo "📋 Module Status:"
        cat "$LOG_DIR/module_status.log"
        echo ""
    } >> "$summary_file"
    
    echo "📁 Output directory: $OUTPUT_DIR"
    echo "📄 Full log: $LOG_DIR/recon.log"
    echo ""
}

# ============================================================================
# MAIN PIPELINE
# ============================================================================

main_pipeline() {
    # Phase 1: Subdomain enumeration
    run_module "Subdomain Enumeration" mod_subdomain_enum "subfinder"
    
    # Gate check: Must have subdomains to continue
    if [[ ! -s "$SUBDOMAINS_DIR/all_subdomains.txt" ]]; then
        log_error "No subdomains found. Cannot continue."
        return 1
    fi
    
    # Phase 2: Live host detection (CRITICAL GATE)
    run_module "Live Host Detection" mod_live_detection "httpx"
    
    # Gate check: live.txt is the source of truth for all downstream modules
    if [[ ! -s "$LIVE_DIR/live.txt" ]]; then
        log_warn "No live hosts in live.txt - downstream modules will be skipped."
    fi
    
    # Phase 3: Parallel data gathering
    run_module "Screenshots" mod_screenshot "gowitness"
    run_module "Historical URLs" mod_url_harvest_gau "gau"
    run_module "Live Crawl" mod_url_harvest_katana "katana"
    
    # Phase 4: Processing
    run_module "URL Merge" mod_url_merge ""
    run_module "JS Discovery" mod_js_discovery ""
    run_module "Parameter Extraction" mod_param_extract "unfurl"
    
    # Phase 5: Analysis
    run_module "Interesting Endpoints" mod_interesting_endpoints ""
    
    # Generate summary
    generate_summary
    
    return 0
}

# ============================================================================
# HELP & USAGE
# ============================================================================

show_banner() {
    echo -e "${CYAN}"
    echo " ██████╗ ██████╗ ███████╗██╗   ██╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
    echo "██╔═══██╗██╔══██╗██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
    echo "██║   ██║██████╔╝███████╗██║   ██║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
    echo "██║   ██║██╔══██╗╚════██║██║   ██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
    echo "╚██████╔╝██║  ██║███████║╚██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
    echo " ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
    echo -e "${NC}"
    echo "  Bug Bounty Recon Framework v$VERSION"
    detect_environment
    echo "  Environment: $ENVIRONMENT"
    echo ""
}

show_help() {
    show_banner
    echo "Usage: $0 <domain> [options]"
    echo ""
    echo "Options:"
    echo "  --install    Install all required dependencies"
    echo "  --check      Run preflight checks without recon"
    echo "  --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 example.com              # Run full recon"
    echo "  $0 --install                # Install dependencies"
    echo "  $0 --check                  # Check tool availability"
    echo ""
    echo "Output Structure:"
    echo "  recon/"
    echo "  ├── subdomains/     Discovered subdomains"
    echo "  ├── live/           Live hosts (HTTP/HTTPS)"
    echo "  ├── screenshots/    Visual screenshots"
    echo "  ├── js/             JavaScript files and endpoints"
    echo "  ├── urls/           All discovered URLs"
    echo "  ├── params/         Extracted parameters"
    echo "  ├── interesting/    High-value endpoints"
    echo "  └── logs/           Execution logs"
    echo ""
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

main() {
    # Handle flags
    case "${1:-}" in
        --help|-h)
            show_help
            exit 0
            ;;
        --install)
            show_banner
            setup_go_env
            install_dependencies
            exit $?
            ;;
        --check)
            show_banner
            setup_go_env
            run_preflight_check
            exit $?
            ;;
        "")
            show_help
            exit 1
            ;;
    esac
    
    # Validate domain
    DOMAIN=$(validate_domain "$1")
    if [[ -z "$DOMAIN" ]]; then
        exit 1
    fi
    
    show_banner
    log_info "Target domain: $DOMAIN"
    
    # Setup Go environment
    if ! setup_go_env; then
        log_error "Failed to setup Go environment"
        exit 1
    fi
    
    # Setup output directory
    OUTPUT_DIR="./recon-$DOMAIN-$(date +%d-%m-%Y_%H-%M)"
    setup_directories "$OUTPUT_DIR"
    
    log_info "Output directory: $OUTPUT_DIR"
    
    # Run main pipeline
    local start_time
    start_time=$(date +%s)
    
    main_pipeline
    
    local end_time
    end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    echo ""
    log_success "Recon completed in ${total_duration}s"
    echo ""
}

# Run main
main "$@"
