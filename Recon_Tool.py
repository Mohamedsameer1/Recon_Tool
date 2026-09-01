#!/usr/bin/env python3
"""
subscan.py — Subdomain enumeration + HTTP status + open-port checker

Usage:
    python3 subscan.py -d example.com
    python3 subscan.py -d example.com -w wordlist.txt
    python3 subscan.py -d example.com -p 80,443,8080,8443 -o results.csv

What it does:
    1. Passive enumeration via crt.sh (certificate transparency logs)
    2. Optional active enumeration via DNS brute force against a wordlist
    3. Resolves each candidate subdomain (DNS A/AAAA lookup)
    4. Checks HTTP/HTTPS status code for live subdomains
    5. Checks a set of common ports for open/closed state (TCP connect scan)
    6. Prints a summary table and optionally writes CSV

Only use against domains/scopes you are authorized to test (your own
infra, or an active bug bounty / pentest engagement scope).
"""

import argparse
import concurrent.futures
import csv
import socket
import sys
import time
import urllib.request
import json
import re

DEFAULT_PORTS = [21, 22, 25, 80, 443, 8000, 8080, 8443, 3000, 3306]
CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
HTTP_TIMEOUT = 5
PORT_TIMEOUT = 2


def _clean_name(name, domain):
    name = name.strip().lower()
    if name.startswith("*."):
        name = name[2:]
    if name.endswith(domain) and re.match(r"^[a-z0-9.\-_]+$", name):
        return name
    return None


def get_subdomains_crtsh(domain, retries=3, timeout=30):
    """Passive enumeration via crt.sh certificate transparency logs.
    crt.sh is notoriously slow/flaky, so retry with backoff before giving up."""
    subs = set()
    url = CRTSH_URL.format(domain=domain)
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "subscan/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read().decode("utf-8", errors="ignore")
            entries = json.loads(data)
            for entry in entries:
                for name in entry.get("name_value", "").split("\n"):
                    clean = _clean_name(name, domain)
                    if clean:
                        subs.add(clean)
            return subs  # success
        except Exception as e:
            print(f"[!] crt.sh attempt {attempt}/{retries} failed: {e}", file=sys.stderr)
            if attempt < retries:
                time.sleep(2 * attempt)
    return subs


def get_subdomains_otx(domain, timeout=15):
    """Passive enumeration via AlienVault OTX passive DNS."""
    subs = set()
    url = OTX_URL.format(domain=domain)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "subscan/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        for record in data.get("passive_dns", []):
            clean = _clean_name(record.get("hostname", ""), domain)
            if clean:
                subs.add(clean)
    except Exception as e:
        print(f"[!] OTX lookup failed: {e}", file=sys.stderr)
    return subs


def get_subdomains_hackertarget(domain, timeout=15):
    """Passive enumeration via HackerTarget's free hostsearch API."""
    subs = set()
    url = HACKERTARGET_URL.format(domain=domain)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "subscan/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode("utf-8", errors="ignore")
        if "API count exceeded" in data or "error" in data.lower():
            return subs
        for line in data.splitlines():
            host = line.split(",")[0]
            clean = _clean_name(host, domain)
            if clean:
                subs.add(clean)
    except Exception as e:
        print(f"[!] HackerTarget lookup failed: {e}", file=sys.stderr)
    return subs


def get_subdomains_subfinder(domain, timeout=120):
    """Shell out to subfinder if it's installed — usually the most reliable source."""
    import subprocess
    subs = set()
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=timeout
        )
        for line in result.stdout.splitlines():
            clean = _clean_name(line, domain)
            if clean:
                subs.add(clean)
    except FileNotFoundError:
        print("[!] subfinder not found on PATH — skipping (install it or drop -s)", file=sys.stderr)
    except Exception as e:
        print(f"[!] subfinder run failed: {e}", file=sys.stderr)
    return subs


def get_subdomains_bruteforce(domain, wordlist_path):
    """Active enumeration: try each word as a subdomain and see if it resolves."""
    candidates = set()
    try:
        with open(wordlist_path) as f:
            words = [w.strip() for w in f if w.strip() and not w.startswith("#")]
    except OSError as e:
        print(f"[!] Could not read wordlist: {e}", file=sys.stderr)
        return candidates

    def try_word(word):
        fqdn = f"{word}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except socket.error:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        for result in ex.map(try_word, words):
            if result:
                candidates.add(result)
    return candidates


def resolve(sub):
    try:
        ip = socket.gethostbyname(sub)
        return sub, ip
    except socket.error:
        return sub, None


def check_http(sub):
    """Return (scheme, status_code) for the first scheme that responds, else (None, None)."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{sub}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "subscan/1.0"}, method="GET")
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return scheme, resp.status
        except urllib.error.HTTPError as e:
            # Still a valid response (e.g. 403/404) — the host is alive
            return scheme, e.code
        except Exception:
            continue
    return None, None


def check_ports(ip, ports):
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(PORT_TIMEOUT)
        try:
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except socket.error:
            pass
        finally:
            s.close()
    return open_ports


def scan_target(sub, ports):
    sub, ip = resolve(sub)
    if not ip:
        return {"subdomain": sub, "ip": None, "status": "NO_DNS", "http_status": None, "open_ports": []}
    scheme, code = check_http(sub)
    open_ports = check_ports(ip, ports)
    return {
        "subdomain": sub,
        "ip": ip,
        "status": "UP" if (code or open_ports) else "DOWN",
        "http_status": f"{scheme.upper()} {code}" if code else "-",
        "open_ports": open_ports,
    }


def main():
    parser = argparse.ArgumentParser(description="Subdomain enumeration + status/port checker")
    parser.add_argument("-d", "--domain", required=True, help="Target root domain, e.g. example.com")
    parser.add_argument("-w", "--wordlist", help="Optional wordlist for active DNS brute force")
    parser.add_argument("-p", "--ports", help="Comma-separated ports to check (default: common set)")
    parser.add_argument("-o", "--output", help="Write results to this CSV file")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Concurrent workers (default 30)")
    parser.add_argument("-s", "--subfinder", action="store_true",
                         help="Also run subfinder (if installed) and merge its results — recommended")
    parser.add_argument("--no-crtsh", action="store_true", help="Skip crt.sh (useful if it's timing out for you)")
    args = parser.parse_args()

    ports = DEFAULT_PORTS
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]

    banner = r"""
   _____      _              _____       _           _   _
  / ____|    | |            |_   _|     (_)         | | (_)
 | |    _   _| |__   ___ _ __ | | _ __  _  ___  ___| |_ _  ___  _ __
 | |   | | | | '_ \ / _ \ '__|| || '_ \| |/ _ \/ __| __| |/ _ \| '_ \
 | |___| |_| | |_) |  __/ |  _| || | | | |  __/ (__| |_| | (_) | | | |
  \_____\__, |_.__/ \___|_| |_____|_| |_|_|\___|\___|\__|_|\___/|_| |_|
         __/ |
        |___/
                    by CyberInjection
                created by Muhamed Sameer
"""
    print(banner)

    domain = args.domain.lower().strip()
    print(f"[*] Enumerating subdomains for {domain} ...")

    subs = {domain}

    if not args.no_crtsh:
        crtsh_subs = get_subdomains_crtsh(domain)
        print(f"[*] crt.sh returned {len(crtsh_subs)} candidate(s)")
        subs |= crtsh_subs

    otx_subs = get_subdomains_otx(domain)
    print(f"[*] AlienVault OTX returned {len(otx_subs)} candidate(s)")
    subs |= otx_subs

    ht_subs = get_subdomains_hackertarget(domain)
    print(f"[*] HackerTarget returned {len(ht_subs)} candidate(s)")
    subs |= ht_subs

    if args.subfinder:
        print("[*] Running subfinder ...")
        sf_subs = get_subdomains_subfinder(domain)
        print(f"[*] subfinder returned {len(sf_subs)} candidate(s)")
        subs |= sf_subs

    if args.wordlist:
        print(f"[*] Brute-forcing with wordlist: {args.wordlist}")
        brute = get_subdomains_bruteforce(domain, args.wordlist)
        print(f"[*] Brute force resolved {len(brute)} additional candidate(s)")
        subs |= brute

    subs = sorted(subs)
    print(f"[*] Total unique candidates: {len(subs)}")
    print(f"[*] Checking DNS / HTTP status / ports {ports} ...\n")

    results = []
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan_target, s, ports): s for s in subs}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda r: (r["status"] != "UP", r["subdomain"]))

    print(f"{'SUBDOMAIN':40} {'IP':16} {'STATUS':8} {'HTTP':14} OPEN PORTS")
    print("-" * 100)
    up_count = 0
    for r in results:
        if r["status"] == "UP":
            up_count += 1
        ports_str = ",".join(str(p) for p in r["open_ports"]) if r["open_ports"] else "-"
        ip_str = r["ip"] or "-"
        print(f"{r['subdomain']:40} {ip_str:16} {r['status']:8} {str(r['http_status']):14} {ports_str}")

    elapsed = time.time() - start
    print("-" * 100)
    print(f"[*] Done in {elapsed:.1f}s — {up_count}/{len(results)} hosts UP")

    if args.output:
        with open(args.output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["subdomain", "ip", "status", "http_status", "open_ports"])
            writer.writeheader()
            for r in results:
                row = dict(r)
                row["open_ports"] = ";".join(str(p) for p in r["open_ports"])
                writer.writerow(row)
        print(f"[*] Results written to {args.output}")


if __name__ == "__main__":
    main()
