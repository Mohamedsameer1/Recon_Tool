# subscan

Subdomain enumeration + HTTP status + open-port checker.

Created by **Muhamed Sameer** ([CyberInjection]([https://github.com/](https://github.com/Mohamedsameer1))).

## What it does

1. **Passive enumeration** — pulls subdomains from crt.sh (certificate transparency), AlienVault OTX passive DNS, and HackerTarget's hostsearch API
2. **Active enumeration (optional)** — DNS brute force against a wordlist you supply
3. **subfinder integration (optional)** — merges in results from [subfinder](https://github.com/projectdiscovery/subfinder) if it's installed
4. **DNS resolution** — filters candidates down to ones that actually resolve
5. **HTTP status check** — hits each live host over HTTPS/HTTP and records the response code
6. **Port scan** — TCP connect scan against a configurable port list
7. **Output** — sorted table in the terminal, optional CSV export

## Requirements

- Python 3.8+
- No third-party Python packages required (standard library only)
- Optional: [subfinder](https://github.com/projectdiscovery/subfinder) on your `PATH` if you want to use `-s`

## Usage

```bash
# Basic run — passive sources only
python3 subscan.py -d example.com

# Include subfinder results
python3 subscan.py -d example.com -s

# Add active DNS brute force with a wordlist
python3 subscan.py -d example.com -w wordlist.txt

# Custom ports, save to CSV
python3 subscan.py -d example.com -p 80,443,8080,8443 -o results.csv

# Skip crt.sh (it can be slow/flaky) and rely on OTX + HackerTarget + subfinder
python3 subscan.py -d example.com --no-crtsh -s
```

### Options

| Flag | Description |
|---|---|
| `-d, --domain` | Target root domain (required) |
| `-w, --wordlist` | Wordlist for active DNS brute force |
| `-p, --ports` | Comma-separated ports to check (default: 21,22,25,80,443,8000,8080,8443,3000,3306) |
| `-o, --output` | Write results to a CSV file |
| `-t, --threads` | Concurrent worker threads (default: 30) |
| `-s, --subfinder` | Also run subfinder and merge its results |
| `--no-crtsh` | Skip crt.sh lookup |

## Legal / scope notice

This tool performs active reconnaissance (DNS brute force, HTTP requests, TCP port scans) against the domains you target. Only run it against:

- Infrastructure you own, or
- Targets explicitly within scope of a bug bounty program or signed pentest engagement you're authorized for

Scanning out-of-scope or unauthorized targets may violate computer misuse laws and bug bounty program terms.
