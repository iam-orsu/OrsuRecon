# Bug Bounty Recon Framework

Production-grade automated reconnaissance framework for Kali Linux on WSL.

## Quick Start

```bash
# 1. Make executable
chmod +x recon.sh

# 2. Install dependencies (first time only)
./recon.sh --install

# 3. Run recon
./recon.sh example.com
```

## Commands

| Command                | Description                |
| ---------------------- | -------------------------- |
| `./recon.sh <domain>`  | Run full reconnaissance    |
| `./recon.sh --install` | Install all dependencies   |
| `./recon.sh --check`   | Validate tool installation |
| `./recon.sh --help`    | Show usage information     |

## Output Structure

```
recon-<domain>-<timestamp>/
├── subdomains/      # Discovered subdomains
│   ├── subfinder.txt
│   ├── amass.txt
│   └── all.txt      # Merged, deduplicated
├── live/            # HTTP/HTTPS validated hosts
│   ├── alive.txt
│   └── alive.json
├── screenshots/     # Visual captures (PNG)
├── js/              # JavaScript analysis
│   ├── files.txt    # .js file URLs
│   └── endpoints.txt # API endpoints
├── urls/            # All discovered URLs
│   ├── gau.txt      # Historical
│   ├── katana.txt   # Live crawl
│   └── all.txt      # Merged
├── params/          # Extracted parameters
│   ├── raw.txt
│   ├── unique.txt
│   └── filtered.txt # Without tracking params
├── interesting/     # High-value endpoints
│   ├── auth.txt
│   ├── admin.txt
│   ├── api.txt
│   ├── debug.txt
│   ├── files.txt
│   └── config.txt
└── logs/
    ├── recon.log
    └── module_status.log
```

## Tools Used

| Tool      | Purpose                       | Install Source |
| --------- | ----------------------------- | -------------- |
| subfinder | Passive subdomain enumeration | `go install`   |
| amass     | Additional subdomain sources  | `go install`   |
| httpx     | HTTP/HTTPS probing            | `go install`   |
| gowitness | Screenshots                   | `go install`   |
| gau       | Historical URL harvesting     | `go install`   |
| katana    | Live crawling                 | `go install`   |
| unfurl    | Parameter extraction          | `go install`   |

## WSL Notes

- **First run**: Execute `./recon.sh --install` to install all dependencies
- **Screenshots**: Uses Chromium with `--no-sandbox` for WSL compatibility
- **PATH**: Go binaries are installed to `$HOME/go/bin` (auto-added to PATH)
- **Output**: Always outputs to Linux filesystem, not `/mnt/c/`

## Configuration

Edit variables at the top of `recon.sh`:

```bash
# Timeouts (seconds)
TIMEOUT_SUBDOMAIN=600    # 10 min
TIMEOUT_HTTPX=300        # 5 min
TIMEOUT_SCREENSHOT=600   # 10 min

# Rate limits
RATE_HTTPX=50            # Concurrent threads
RATE_CRAWL=10            # Crawl concurrency
```

## Safe Extensions

### Adding New Subdomain Sources

```bash
# Add to mod_subdomain_enum function
mod_subdomain_enum() {
    # ... existing code ...

    # Add new source
    if command -v new_tool &>/dev/null; then
        log_info "Running new_tool..."
        new_tool -d "$DOMAIN" -o "$SUBDOMAINS_DIR/new_tool.txt"
    fi

    # Merge happens automatically from all .txt files
}
```

### Adding New Interesting Patterns

```bash
# Add to mod_interesting_endpoints function
grep -iE '(payment|checkout|billing|stripe|paypal)' "$input" | \
    sort -u > "$INTERESTING_DIR/payment.txt"
```

### Adding API Key Support

For subfinder API keys, create `~/.config/subfinder/provider-config.yaml`:

```yaml
securitytrails:
  - YOUR_API_KEY
shodan:
  - YOUR_API_KEY
virustotal:
  - YOUR_API_KEY
```

### Custom Post-Processing

Add hooks at the end of `main_pipeline`:

```bash
main_pipeline() {
    # ... existing modules ...

    # Custom post-processing
    run_module "Custom Analysis" my_custom_module ""
}

my_custom_module() {
    # Your custom logic here
    log_info "Running custom analysis..."
}
```

## Troubleshooting

| Issue                   | Solution                               |
| ----------------------- | -------------------------------------- |
| `go: command not found` | `sudo apt install golang-go`           |
| Tool not in PATH        | Restart terminal or `source ~/.bashrc` |
| Screenshots fail        | Check chromium: `chromium --version`   |
| Timeouts on large scope | Increase `TIMEOUT_*` values            |
| Rate limited            | Reduce `RATE_*` values                 |

## Legal Notice

⚠️ **Only run against targets you have explicit authorization to test.**

This tool is designed for:

- Bug bounty programs where recon is permitted
- Authorized penetration testing engagements
- Your own domains and infrastructure

Unauthorized scanning may violate laws and terms of service.

## License

MIT License - Use responsibly.
