# CyberInjection - Passive Reconnaissance Tool

A Python tool to find all subdomains of a target domain and check which ones are live/active.

## Features

- **Certificate Transparency (crt.sh)**: Queries certificate transparency logs for discovered subdomains
- **DNS Enumeration**: Tests common subdomain prefixes using DNS resolution
- **VirusTotal Integration**: Optional integration with VirusTotal API for additional subdomain discovery
- **Live Host Detection**: Checks HTTP/HTTPS status codes to determine which subdomains are active
- **Multi-threaded**: Uses concurrent threads for faster verification
- **JSON Export**: Exports results to a JSON file for further analysis
- **Cross-platform**: Works on Linux, macOS, and Windows
- **Interactive Interface**: Simple command-line prompts for easy use

## Installation

```bash
# Clone or navigate to the tool directory
cd /path/to/CyberInjection

# Install dependencies
pip install -r requirements.txt
```

## Usage

Simply run the tool and follow the interactive prompts:

```bash
python Recon_Tool.py
```

The tool will ask you for:
1. **Target domain** - The domain to scan (e.g., example.com)
2. **Number of threads** - How many concurrent checks to run (default: 10, recommended: 10-50)
3. **VirusTotal API key** - Optional additional subdomain source

### Example Session:

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                    CYBERINJECTION                           ║
║              Passive Reconnaissance Tool v1.0               ║
║                                                              ║
║            Find & Verify Live Subdomains                   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

[*] Enter the target domain (e.g., example.com):
    > example.com

[*] Enter number of threads (default: 10, recommended: 10-50):
    > 20

[*] Do you have a VirusTotal API key? (y/n, default: n):
    > n
```

## How It Works

1. **Subdomain Discovery**:
   - Queries crt.sh for subdomains found in certificate transparency logs
   - Tests common subdomain prefixes (www, mail, api, admin, etc.) via DNS
   - Optionally queries VirusTotal for additional subdomains (requires API key)

2. **Live Host Verification**:
   - Makes HTTP/HTTPS requests to each discovered subdomain
   - Records HTTP status codes
   - Identifies "live" subdomains (status codes 2xx-4xx)
   - Uses multi-threading for faster checks

3. **Results**:
   - Displays live subdomains in the terminal
   - Exports results to `subdomains.json`

## Output

The tool displays:
- Total subdomains discovered
- Live subdomains with HTTP status codes
- A JSON file with all results

Example output:
```
============================================================
RESULTS - Live Subdomains
============================================================

Subdomain                                Status Code     Status
----------------------------------------
api.example.com                          200             LIVE
www.example.com                          301             LIVE
admin.example.com                        404             LIVE
dev.example.com                          0               DEAD

[+] Total live subdomains: 3
```

## Notes

- This is a **passive recon** tool - it doesn't actively scan targets aggressively
- Requires an internet connection to query crt.sh and VirusTotal
- VirusTotal API key is optional but provides additional subdomain sources
- Common status codes:
  - 2xx: Successful (resource found and accessible)
  - 3xx: Redirect (resource exists but redirects)
  - 4xx: Client error (page not found but server responds)
  - 5xx: Server error (service is having issues)
  - 0: No response (dead/unreachable)

## Getting a VirusTotal API Key

1. Visit https://www.virustotal.com
2. Create a free account or sign in
3. Go to your API key in account settings
4. Use it with the tool when prompted

## Security Notes

- Only use this tool on systems you own or have explicit permission to scan
- Respect legal and ethical guidelines for penetration testing
- The tool does not perform active attacks or aggressive scans
- Be mindful of rate limiting on public APIs

## System Requirements

- Python 3.6+
- Linux, macOS, or Windows
- Internet connection

