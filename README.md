# OrsuRecon v3 — Elite Bug Bounty Recon Framework

Production-grade automated reconnaissance framework for Kali Linux, Ubuntu VPS, and WSL.

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

| Command                            | Description                              |
| ---------------------------------- | ---------------------------------------- |
| `./recon.sh <domain>`              | Run standard recon                       |
| `./recon.sh <domain> --all`        | Run full recon with ALL features enabled |
| `./recon.sh -l <file>`             | Process domain list (with sub enum)      |
| `./recon.sh -l <file> -ns`         | Process target list (no sub enum)        |
| `./recon.sh --install`             | Install all dependencies                 |
| `./recon.sh --check`               | Validate tool installation               |
| `./recon.sh --help`                | Show usage information                   |

## v3 Pipeline (18 Stages)

```
┌───────────────────────────────────────────────────────────────┐
│                     OrsuRecon v3 Pipeline                      │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│   1.  Subdomain Enumeration      (subfinder, assetfinder)     │
│   2.  DNS Resolution + Perms     (alterx, puredns, dnsx) NEW  │
│   3.  Live Host Probing          (httpx)                      │
│   4.  Port Scanning              (masscan → nmap)        NEW  │
│   5.  Tech Fingerprinting        (whatweb, wafw00f)      NEW  │
│   6.  Screenshots                (gowitness)             NEW  │
│   7.  URL Collection             (gau, waybackurls, katana)   │
│   8.  Content Fuzzing            (ffuf)                  NEW  │
│   9.  JS Analysis                (jsluice, source maps)  UPG  │
│  10.  Parameter Discovery        (ParamSpider, Arjun)         │
│  11.  Pattern Matching           (gf patterns)                │
│  12.  Subdomain Takeover         (subzy, nuclei)         NEW  │
│  13.  CORS Scanning              (Corsy)                 NEW  │
│  14.  Cloud Bucket Enum          (cloud_enum)            NEW  │
│  15.  GitHub Secret Scanning     (trufflehog)            NEW  │
│  16.  Nuclei Vuln Scan           (nuclei)                     │
│  17.  OOB Blind Testing          (interactsh)            NEW  │
│  18.  Summary & Report                                        │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

## Feature Flags

| Flag               | Default | Description                                 |
| ------------------- | ------- | ------------------------------------------- |
| `--ports`           | OFF     | Port scanning (masscan + nmap)              |
| `--fuzz`            | OFF     | Directory/content fuzzing (ffuf)            |
| `--deep-js`         | ON      | Source maps + jsluice deep JS analysis      |
| `--takeover`        | ON      | Subdomain takeover detection (subzy)        |
| `--cors`            | ON      | CORS misconfiguration scanning              |
| `--cloud`           | OFF     | Cloud bucket enumeration (S3/Azure/GCP)     |
| `--github`          | OFF     | GitHub secret scanning (needs GITHUB_TOKEN) |
| `--screenshots`     | ON      | Screenshot capture (gowitness)              |
| `--stealth`         | OFF     | Passive-only — no active scanning           |
| `--all`             | —       | Enable ALL features                         |
| `-n, --nuclei`      | OFF     | Nuclei vulnerability scanning               |

## Output Structure

```
recon-output/<domain>/
├── subdomains/        # Discovered subdomains
│   ├── all.txt        # Merged, deduplicated, resolved
│   ├── ips.txt        # Extracted IP addresses
│   └── cnames.txt     # CNAME records (for takeover)
├── ports/             # Port scan results
│   ├── open_ports.txt
│   ├── interesting_ports.txt  # Non-80/443 ports
│   └── nmap_results.txt
├── tech/              # Technology fingerprints
│   ├── fingerprints.txt
│   └── waf_results.txt
├── screenshots/       # Visual captures (PNG)
├── urls/              # All discovered URLs
│   ├── all_urls.txt
│   └── inscope_urls.txt
├── fuzzing/           # ffuf directory findings
│   └── all_findings.txt
├── js/                # JavaScript analysis
│   ├── js_urls.txt
│   ├── jsluice_urls.txt      # Deep endpoint extraction
│   ├── jsluice_secrets.txt   # Secret patterns
│   ├── sourcemaps/           # .js.map files (full source!)
│   ├── api_routes.txt        # /api/, /v1/, /internal/ routes
│   ├── internal_ips.txt      # 10.x, 192.168.x, 172.x IPs
│   └── dom_sinks.txt         # XSS-prone DOM patterns
├── endpoints/         # All discovered endpoints
├── params/            # GF pattern matches
│   ├── xss.txt, sqli.txt, ssrf.txt, lfi.txt
│   └── redirect.txt, idor.txt
├── takeover/          # Subdomain takeover results
│   ├── subzy_results.txt
│   └── cname_map.txt
├── vulns/             # Vulnerability findings
│   ├── cors_results.json
│   └── cors_vulnerable.txt
├── cloud/             # Cloud bucket discoveries
├── secrets/           # GitHub leaked secrets
│   └── trufflehog_results.json
├── oob/               # Out-of-band testing
│   └── blind_testing_url.txt
└── logs/
    ├── recon.log
    ├── errors.log
    └── summary.txt
```

## Tools Used (30+)

| Tool | Purpose | Source |
| --- | --- | --- |
| subfinder | Passive subdomain enumeration | `go install` |
| assetfinder | Additional subdomain sources | `go install` |
| alterx | Subdomain permutation generation | `go install` |
| puredns | DNS resolution + wildcard filtering | `go install` |
| dnsx | DNS record queries (A, CNAME) | `go install` |
| httpx | HTTP/HTTPS probing + tech detect | `go install` |
| masscan | Fast port scanning | `apt install` |
| nmap | Service/version detection | `apt install` |
| whatweb | Technology fingerprinting | `apt install` |
| wafw00f | WAF detection | `apt install` |
| gowitness | Screenshot capture | `go install` |
| gau | Historical URL harvesting | `go install` |
| waybackurls | Wayback Machine URLs | `go install` |
| katana | Live crawling | `go install` |
| hakrawler | Additional crawling | `go install` |
| ffuf | Directory/content fuzzing | `go install` |
| jsluice | Advanced JS analysis (AST-based) | `go install` |
| LinkFinder | JS endpoint extraction | `git clone` |
| SecretFinder | JS secret detection | `git clone` |
| ParamSpider | Parameter discovery | `git clone` |
| arjun | Hidden parameter detection | `pip install` |
| gf | Pattern-based URL matching | `go install` |
| subzy | Subdomain takeover detection | `go install` |
| Corsy | CORS misconfiguration scanner | `git clone` |
| cloud_enum | S3/Azure/GCP bucket discovery | `git clone` |
| trufflehog | GitHub secret scanning | `go install` |
| nuclei | Vulnerability scanning | `go install` |
| interactsh | Out-of-band blind testing | `go install` |

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `DISCORD_WEBHOOK` | Discord webhook URL for notifications |
| `GITHUB_TOKEN` | GitHub personal access token for trufflehog |

## Examples

```bash
# Standard recon on a single domain
./recon.sh example.com

# Full recon with ALL features enabled
./recon.sh example.com --all

# Add port scanning and fuzzing
./recon.sh example.com --ports --fuzz

# Process domain list (enumerate subs first)
./recon.sh -l domains.txt

# Explicit targets, no sub enumeration
./recon.sh -l targets.txt -ns

# Passive-only recon (stealth mode)
./recon.sh example.com --stealth

# GitHub + cloud scanning
GITHUB_TOKEN="ghp_..." ./recon.sh example.com --github --cloud

# Custom fuzzing wordlist
./recon.sh example.com --fuzz --wordlist /path/to/wordlist.txt

# Resume a failed/interrupted scan
./recon.sh example.com

# Restart fresh (ignore checkpoint)
./recon.sh example.com --fresh
```

## Configuration

Edit variables at the top of `recon.sh`:

```bash
# Timeouts (seconds)
STAGE_TIMEOUT=300        # Per-stage timeout

# Rate limits
THREADS=5                # Concurrent threads
RATE_LIMIT_DELAY=5       # Delay between API-heavy tools

# JS analysis
JS_DOWNLOAD_LIMIT=200    # Max JS files to download
JS_PARALLEL_DOWNLOADS=10 # Concurrent JS downloads
```

## Troubleshooting

| Issue | Solution |
| --- | --- |
| `go: command not found` | `sudo apt install golang-go` |
| Tool not in PATH | Restart terminal or `source ~/.bashrc` |
| Screenshots fail | Check chromium: `chromium --version` |
| Timeouts on large scope | Increase `--timeout` value |
| Rate limited | Increase `--rate-delay` value |
| masscan needs root | Run with `sudo` or as root |
| puredns no results | Check resolvers: `$HOME/tools/resolvers.txt` |

## Legal Notice

⚠️ **Only run against targets you have explicit authorization to test.**

This tool is designed for:

- Bug bounty programs where recon is permitted
- Authorized penetration testing engagements
- Your own domains and infrastructure

Unauthorized scanning may violate laws and terms of service.

## License

MIT License - Use responsibly.
