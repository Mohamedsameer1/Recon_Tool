#!/usr/bin/env python3
"""
Passive Recon Tool - Find and verify live subdomains
"""

import requests
import subprocess
import json
import sys
from typing import Set, List, Tuple
from urllib.parse import urlparse
import socket
import threading
from collections import defaultdict
import time

class PassiveReconTool:
    def __init__(self, domain: str, timeout: int = 5, threads: int = 10):
        """
        Initialize the recon tool
        
        Args:
            domain: Target domain to scan
            timeout: Request timeout in seconds
            threads: Number of concurrent threads for checking live hosts
        """
        self.domain = domain
        self.timeout = timeout
        self.threads = threads
        self.subdomains: Set[str] = set()
        self.live_subdomains: List[Tuple[str, int]] = []
        self.lock = threading.Lock()
        
    def get_subdomains_crt_sh(self) -> Set[str]:
        """Get subdomains from crt.sh (Certificate Transparency logs)"""
        print("[*] Querying crt.sh for subdomains...")
        subdomains = set()
        
        try:
            # Query crt.sh API for certificate transparency logs
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        # Extract domains from name_value (can contain multiple domains)
                        for subdomain in name_value.split('\n'):
                            subdomain = subdomain.strip()
                            if subdomain and self.domain in subdomain:
                                subdomains.add(subdomain)
                except:
                    pass
        except requests.exceptions.RequestException as e:
            print(f"[-] Error querying crt.sh: {e}")
        
        print(f"[+] Found {len(subdomains)} subdomains from crt.sh")
        return subdomains
    
    def get_subdomains_dns(self) -> Set[str]:
        """Get subdomains using DNS lookups (common subdomains)"""
        print("[*] Checking common subdomains via DNS...")
        subdomains = set()
        
        # Common subdomain prefixes
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'admin', 'api', 'app',
            'dev', 'staging', 'test', 'prod', 'cdn', 'static', 'blog', 'shop',
            'git', 'github', 'gitlab', 'jenkins', 'jira', 'slack', 'zoom',
            'mail1', 'mail2', 'webserver', 'database', 'backup', 'vpn',
            'remote', 'secure', 'portal', 'login', 'auth', 'oauth'
        ]
        
        for prefix in common_subdomains:
            subdomain = f"{prefix}.{self.domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.add(subdomain)
            except socket.gaierror:
                pass
            except Exception:
                pass
        
        print(f"[+] Found {len(subdomains)} live subdomains via DNS")
        return subdomains
    
    def get_subdomains_virustotal(self, api_key: str = None) -> Set[str]:
        """Get subdomains from VirusTotal (requires API key)"""
        subdomains = set()
        
        if not api_key:
            return subdomains
        
        print("[*] Querying VirusTotal for subdomains...")
        try:
            headers = {"x-apikey": api_key}
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    subdomain = item.get('id', '')
                    if subdomain:
                        subdomains.add(subdomain)
        except Exception as e:
            print(f"[-] Error querying VirusTotal: {e}")
        
        return subdomains
    
    def check_subdomain_live(self, subdomain: str) -> Tuple[str, int, bool]:
        """
        Check if a subdomain is live
        
        Args:
            subdomain: Subdomain to check
            
        Returns:
            Tuple of (subdomain, status_code, is_live)
        """
        # Try HTTPS first, then HTTP
        for protocol in ['https', 'http']:
            url = f"{protocol}://{subdomain}"
            try:
                response = requests.head(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )
                status_code = response.status_code
                
                # Consider 2xx, 3xx, 4xx as "live" (server is responding)
                is_live = status_code < 500
                
                with self.lock:
                    self.live_subdomains.append((subdomain, status_code))
                
                return subdomain, status_code, is_live
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except Exception:
                continue
        
        return subdomain, 0, False
    
    def verify_live_subdomains(self):
        """Check which subdomains are live using threading"""
        print(f"\n[*] Checking {len(self.subdomains)} subdomains for live hosts...")
        
        # Use threading for concurrent checks
        threads = []
        subdomain_list = list(self.subdomains)
        
        for subdomain in subdomain_list:
            while len(threading.enumerate()) > self.threads + 1:
                time.sleep(0.1)
            
            thread = threading.Thread(target=self.check_subdomain_live, args=(subdomain,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Sort by status code
        self.live_subdomains.sort(key=lambda x: x[1])
    
    def scan(self, virustotal_api_key: str = None) -> None:
        """
        Run the complete passive recon scan
        
        Args:
            virustotal_api_key: Optional VirusTotal API key
        """
        print(f"\n{'='*60}")
        print(f"Passive Recon Tool - Target: {self.domain}")
        print(f"{'='*60}\n")
        
        # Gather subdomains from multiple sources
        self.subdomains.update(self.get_subdomains_crt_sh())
        self.subdomains.update(self.get_subdomains_dns())
        
        if virustotal_api_key:
            self.subdomains.update(self.get_subdomains_virustotal(virustotal_api_key))
        
        print(f"\n[+] Total unique subdomains found: {len(self.subdomains)}\n")
        
        if not self.subdomains:
            print("[-] No subdomains found!")
            return
        
        # Verify which subdomains are live
        self.verify_live_subdomains()
        
        # Display results
        self.display_results()
    
    def display_results(self):
        """Display scan results"""
        print(f"\n{'='*60}")
        print("RESULTS - Live Subdomains")
        print(f"{'='*60}\n")
        
        if not self.live_subdomains:
            print("[-] No live subdomains found")
            return
        
        print(f"{'Subdomain':<40} {'Status Code':<15} {'Status':<10}")
        print("-" * 65)
        
        for subdomain, status_code in self.live_subdomains:
            if status_code > 0:
                status = "LIVE" if status_code < 500 else "DEAD"
                print(f"{subdomain:<40} {status_code:<15} {status:<10}")
        
        print(f"\n[+] Total live subdomains: {len([sc for _, sc in self.live_subdomains if sc > 0])}")
    
    def export_results(self, filename: str = "subdomains.json"):
        """Export results to JSON file"""
        results = {
            "domain": self.domain,
            "total_subdomains": len(self.subdomains),
            "live_subdomains": [
                {"subdomain": subdomain, "status_code": status_code}
                for subdomain, status_code in self.live_subdomains
                if status_code > 0
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Results exported to {filename}")


def display_banner():
    """Display tool banner with name"""
    banner = """
    
    ███████████████████████████████████████████████████████████████████████████
    ███████████████████████████████████████████████████████████████████████████
    ██                                                                       ██
    ██                      ██████╗ ██╗   ██╗██████╗ ███████╗██████╗       ██
    ██                     ██╔════╝ ██║   ██║██╔══██╗██╔════╝██╔══██╗      ██
    ██                     ██║  ███╗██║   ██║██████╔╝█████╗  ██████╔╝      ██
    ██                     ██║   ██║██║   ██║██╔══██╗██╔══╝  ██╔══██╗      ██
    ██                     ╚██████╔╝╚██████╔╝██████╔╝███████╗██║  ██║      ██
    ██                      ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝      ██
    ██                                                                       ██
    ██          ██╗███╗   ██╗███████╗███████╗ ██████╗████████╗██╗ ██████╗  ██
    ██          ██║████╗  ██║██╔════╝██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗ ██
    ██          ██║██╔██╗ ██║█████╗  █████╗  ██║        ██║   ██║██║   ██║ ██
    ██          ██║██║╚██╗██║██╔══╝  ██╔══╝  ██║        ██║   ██║██║   ██║ ██
    ██          ██║██║ ╚████║███████╗███████╗╚██████╗   ██║   ██║╚██████╔╝ ██
    ██          ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝  ██
    ██                                                                       ██
    ██              Passive Reconnaissance Tool v1.0                        ██
    ██          Find & Verify Live Subdomains                              ██
    ██                                                                       ██
    ███████████████████████████████████████████████████████████████████████████
    ███████████████████████████████████████████████████████████████████████████
    """
    print(banner)


def main():
    """Main function with interactive input"""
    # Display banner
    display_banner()
    
    try:
        # Get domain from user
        print("\n[*] Enter the target domain (e.g., example.com):")
        domain = input("    > ").strip()
        
        if not domain:
            print("[-] Domain cannot be empty!")
            sys.exit(1)
        
        # Get thread count
        print("\n[*] Enter number of threads (default: 10, recommended: 10-50):")
        threads_input = input("    > ").strip()
        threads = 10
        
        if threads_input:
            try:
                threads = int(threads_input)
                if threads < 1:
                    threads = 10
            except ValueError:
                threads = 10
        
        # Get VirusTotal API key (optional)
        print("\n[*] Do you have a VirusTotal API key? (y/n, default: n):")
        has_api = input("    > ").strip().lower()
        virustotal_api_key = None
        
        if has_api in ['y', 'yes']:
            print("\n[*] Enter your VirusTotal API key:")
            virustotal_api_key = input("    > ").strip()
        
        # Suppress HTTPS warnings
        requests.packages.urllib3.disable_warnings()
        
        # Run the tool
        print("\n")
        tool = PassiveReconTool(domain, threads=threads)
        tool.scan(virustotal_api_key=virustotal_api_key)
        tool.export_results()
        
        print("\n[+] Scan completed! Check 'subdomains.json' for detailed results.")
        
    except KeyboardInterrupt:
        print("\n\n[-] Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
