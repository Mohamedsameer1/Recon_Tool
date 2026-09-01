#!/usr/bin/env python3
"""
CyberInjection - Advanced Subdomain Enumeration Tool (Like Subfinder)
Find all subdomains and verify which ones are live
"""

import requests
import subprocess
import json
import sys
import os
from typing import Set, List, Tuple
from urllib.parse import urlparse
import socket
import threading
from collections import defaultdict
import time
from datetime import datetime

# Color codes for terminal output
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'
    PURPLE = '\033[95m'
    
def print_success(msg):
    print(f"{Colors.GREEN}[+]{Colors.END} {msg}")

def print_info(msg):
    print(f"{Colors.CYAN}[*]{Colors.END} {msg}")

def print_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.END} {msg}")

def print_error(msg):
    print(f"{Colors.RED}[-]{Colors.END} {msg}")

class SubdomainEnumerator:
    def __init__(self, domain: str, timeout: int = 5, threads: int = 15):
        """
        Initialize the subdomain enumerator (Like Subfinder)
        
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
        self.start_time = datetime.now()
        self.sources_used = []
        
    def get_subdomains_crt_sh(self) -> Set[str]:
        """Get subdomains from crt.sh (Certificate Transparency logs)"""
        print_info("Querying crt.sh for subdomains...")
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
            self.sources_used.append("crt.sh")
        except requests.exceptions.RequestException as e:
            print_warning(f"Error querying crt.sh: {e}")
        
        print_success(f"Found {len(subdomains)} subdomains from crt.sh")
        return subdomains
    
    def get_subdomains_dns(self) -> Set[str]:
        """Get subdomains using DNS lookups (common subdomains)"""
        print_info("Checking common subdomains via DNS...")
        subdomains = set()
        
        # Common subdomain prefixes (extended list like subfinder)
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'admin', 'api', 'app',
            'dev', 'staging', 'test', 'prod', 'cdn', 'static', 'blog', 'shop',
            'git', 'github', 'gitlab', 'jenkins', 'jira', 'slack', 'zoom',
            'mail1', 'mail2', 'webserver', 'database', 'backup', 'vpn',
            'remote', 'secure', 'portal', 'login', 'auth', 'oauth', 'api-v1', 'api-v2',
            'docs', 'support', 'help', 'wiki', 'forum', 'community', 'newsletter',
            'status', 'cloud', 'dashboard', 'panel', 'console', 'control',
            'download', 'upload', 'media', 'assets', 'images', 'cdn1', 'cdn2',
            'mx', 'mx1', 'mx2', 'smtp1', 'smtp2', 'imap', 'pop3', 'webdisk'
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
        
        self.sources_used.append("DNS Brute Force")
        print_success(f"Found {len(subdomains)} live subdomains via DNS")
        return subdomains
    
    def get_subdomains_securitytxt(self) -> Set[str]:
        """Get subdomains from security.txt files"""
        print_info("Checking security.txt files...")
        subdomains = set()
        
        paths = ['/.well-known/security.txt', '/security.txt']
        
        for path in paths:
            try:
                url = f"https://{self.domain}{path}"
                response = requests.get(url, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    content = response.text
                    # Look for Contact URLs or other domains
                    for line in content.split('\n'):
                        if 'Contact:' in line or 'contact' in line.lower():
                            parts = line.split(':')
                            if len(parts) > 1:
                                # Try to extract domain
                                for word in parts[1].split():
                                    if self.domain in word or '@' in word:
                                        subdomains.add(word.replace('mailto:', '').replace('https://', '').replace('http://', '').split('/')[0])
            except:
                pass
        
        if subdomains:
            self.sources_used.append("security.txt")
        return subdomains
    
    def get_subdomains_github(self) -> Set[str]:
        """Search GitHub for domain references"""
        print_info("Searching GitHub for subdomains...")
        subdomains = set()
        
        try:
            # Simple GitHub code search (no API key required for basic searches)
            search_queries = [
                self.domain,
                f'"{self.domain}"',
            ]
            
            for query in search_queries:
                url = "https://api.github.com/search/code"
                params = {"q": query, "per_page": 10}
                
                try:
                    response = requests.get(url, params=params, timeout=self.timeout)
                    if response.status_code == 200:
                        data = response.json()
                        # This is limited without auth, so just note the attempt
                        if data.get('total_count', 0) > 0:
                            self.sources_used.append("GitHub")
                            break
                except:
                    pass
        except:
            pass
        
        return subdomains
    
    def get_subdomains_virustotal(self, api_key: str = None) -> Set[str]:
        """Get subdomains from VirusTotal (requires API key)"""
        subdomains = set()
        
        if not api_key:
            return subdomains
        
        print_info("Querying VirusTotal for subdomains...")
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
                self.sources_used.append("VirusTotal")
        except Exception as e:
            print_warning(f"Error querying VirusTotal: {e}")
        
        if subdomains:
            print_success(f"Found {len(subdomains)} subdomains from VirusTotal")
        return subdomains
    
    def get_subdomains_twitter(self) -> Set[str]:
        """Simulate Twitter/X search (passive enumeration idea)"""
        subdomains = set()
        # This would require social media API keys
        # Leaving as placeholder for enterprise version
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
        print_info(f"Verifying {len(self.subdomains)} subdomains for live hosts...")
        print_info(f"Using {self.threads} concurrent threads\n")
        
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
        Run the complete subdomain enumeration scan (Like Subfinder)
        
        Args:
            virustotal_api_key: Optional VirusTotal API key
        """
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.PURPLE}CyberInjection - Subdomain Enumeration{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
        print_info(f"Target: {Colors.BOLD}{self.domain}{Colors.END}")
        print_info(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Gather subdomains from multiple sources
        self.subdomains.update(self.get_subdomains_crt_sh())
        self.subdomains.update(self.get_subdomains_dns())
        self.subdomains.update(self.get_subdomains_securitytxt())
        self.subdomains.update(self.get_subdomains_github())
        
        if virustotal_api_key:
            self.subdomains.update(self.get_subdomains_virustotal(virustotal_api_key))
        
        print(f"\n{Colors.BOLD}Enumeration Summary:{Colors.END}")
        print(f"  Sources used: {', '.join(set(self.sources_used))}")
        print(f"  Total unique subdomains: {Colors.BOLD}{len(self.subdomains)}{Colors.END}\n")
        
        if not self.subdomains:
            print_error("No subdomains found!")
            return
        
        # Verify which subdomains are live
        self.verify_live_subdomains()
        
        # Display results
        self.display_results()
    
    def display_results(self):
        """Display scan results in Subfinder-like format"""
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}LIVE SUBDOMAINS FOUND{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
        
        live_count = len([subdomain for subdomain, sc in self.live_subdomains if sc > 0])
        
        if not live_count:
            print_warning("No live subdomains detected")
            return
        
        print(f"{'Subdomain':<45} {'Status':<15} {'HTTP Code':<10}")
        print("-" * 70)
        
        for subdomain, status_code in self.live_subdomains:
            if status_code > 0:
                if status_code < 300:
                    status = f"{Colors.GREEN}✓ LIVE{Colors.END}"
                    status_text = f"{Colors.GREEN}{status_code}{Colors.END}"
                elif status_code < 400:
                    status = f"{Colors.YELLOW}↻ REDIRECT{Colors.END}"
                    status_text = f"{Colors.YELLOW}{status_code}{Colors.END}"
                elif status_code < 500:
                    status = f"{Colors.CYAN}? CLIENT{Colors.END}"
                    status_text = f"{Colors.CYAN}{status_code}{Colors.END}"
                else:
                    status = f"{Colors.RED}✗ ERROR{Colors.END}"
                    status_text = f"{Colors.RED}{status_code}{Colors.END}"
                
                print(f"{subdomain:<45} {status:<25} {status_text:<10}")
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print_success(f"Total live subdomains: {live_count}")
        print_info(f"Scan completed in {elapsed:.2f} seconds")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
    
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
    ██                     ██║     ║   ██║██████╔╝█████╗  ██████╔╝      ██
    ██                     ██║      ██║   ██║██╔══██╗██╔══╝  ██╔══██╗      ██
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
        print_info("Enter the target domain (e.g., example.com):")
        domain = input(f"    {Colors.CYAN}>{Colors.END} ").strip()
        
        if not domain:
            print_error("Domain cannot be empty!")
            sys.exit(1)
        
        # Check for VirusTotal API key in environment variable
        virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        
        if virustotal_api_key:
            print_success("VirusTotal API key found! Using it for additional subdomains...")
        else:
            print_info("Tip: Set VIRUSTOTAL_API_KEY environment variable to unlock VirusTotal scanning")
            print_info("Get free API at: https://www.virustotal.com\n")
        
        # Suppress HTTPS warnings
        requests.packages.urllib3.disable_warnings()
        
        # Run the tool with default 15 threads for faster scanning
        enumerator = SubdomainEnumerator(domain, threads=15)
        enumerator.scan(virustotal_api_key=virustotal_api_key)
        enumerator.export_results()
        
        print_success("Scan completed! Check 'subdomains.json' for detailed results.")
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}Scan interrupted by user.{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print_error(f"{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
