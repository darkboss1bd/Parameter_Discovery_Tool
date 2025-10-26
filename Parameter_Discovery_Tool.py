import requests
import argparse
import threading
import time
from urllib.parse import urlparse, urljoin, parse_qs
from collections import deque, OrderedDict
import random
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

class DarkBossParameterFinder:
    def __init__(self):
        self.banner = """
\033[1;31m
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  ██████╗  █████╗ ██████╗ ██╗  ██╗██████╗  ██████╗ ███████╗███████╗██████╗   ║
║  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗  ║
║  ██║  ██║███████║██████╔╝█████╔╝ ██████╔╝██║   ██║███████╗███████╗██████╔╝  ║
║  ██║  ██║██╔══██║██╔══██╗██╔═██╗ ██╔══██╗██║   ██║╚════██║╚════██║██╔══██╗  ║
║  ██████╔╝██║  ██║██║  ██║██║  ██╗██████╔╝╚██████╔╝███████║███████║██║  ██║  ║
║  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝  ║
║                                                                              ║
║                    ADVANCED PARAMETER DISCOVERY TOOL                         ║
║                         [ darkboss1bd EDITION ]                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
\033[0m"""
        
        self.contact_info = """
\033[1;36m
📞 CONTACT INFORMATION:
├── 🔥 Telegram ID: https://t.me/darkvaiadmin
├── 📢 Channel: https://t.me/windowspremiumkey  
├── 🌐 Website: https://crackyworld.com/
└── 💼 Professional Security Tools
\033[0m"""
        
        self.common_parameters = [
            # Basic parameters
            'id', 'page', 'view', 'file', 'search', 'query', 'q', 's', 'keyword',
            'category', 'type', 'sort', 'order', 'limit', 'offset', 'start',
            'end', 'date', 'time', 'year', 'month', 'day',
            
            # User parameters
            'user', 'username', 'name', 'firstname', 'lastname', 'email', 
            'password', 'pass', 'pwd', 'login', 'logout', 'register',
            
            # Security parameters
            'token', 'key', 'api', 'api_key', 'secret', 'auth', 'session', 
            'cookie', 'admin', 'debug', 'test', 'mode', 'config',
            
            # System parameters
            'action', 'method', 'cmd', 'command', 'exec', 'system', 'shell',
            'redirect', 'return', 'next', 'ref', 'referer', 'url', 'uri',
            
            # Response parameters
            'status', 'msg', 'message', 'error', 'success', 'warning', 'info',
            'result', 'output', 'response',
            
            # Localization
            'lang', 'language', 'locale', 'country', 'region', 'city',
            
            # E-commerce
            'price', 'amount', 'cost', 'total', 'quantity', 'qty', 'size',
            'color', 'weight', 'currency',
            
            # File parameters
            'upload', 'download', 'filename', 'path', 'dir', 'directory',
            'location', 'address', 'phone', 'mobile'
        ]
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        self.results = OrderedDict()
        self.scan_counter = 1

    def print_banner(self):
        print(self.banner)
        print(self.contact_info)
        print("\n" + "="*80)

    def validate_url(self, url):
        """Validate and format URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid URL provided")
        
        return url

    def test_parameter(self, url, param):
        """Test individual parameter"""
        test_value = f"darkboss1bd_test_{random.randint(10000, 99999)}"
        test_url = self.add_parameter_to_url(url, param, test_value)
        
        try:
            response = requests.get(test_url, headers=self.headers, timeout=10, verify=False)
            
            # Check if parameter is accepted
            if response.status_code in [200, 301, 302, 403]:
                # Check if parameter value is reflected
                is_reflected = test_value in response.text
                
                return {
                    'parameter': param,
                    'url': test_url,
                    'status_code': response.status_code,
                    'reflected': is_reflected,
                    'content_length': len(response.content)
                }
                
        except requests.RequestException as e:
            pass
        
        return None

    def add_parameter_to_url(self, url, param, value):
        """Add parameter to URL properly"""
        parsed = urlparse(url)
        query = parsed.query
        
        if query:
            return f"{url}&{param}={value}"
        else:
            return f"{url}?{param}={value}"

    def extract_parameters_from_url(self, url):
        """Extract existing parameters from URL"""
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)
        return list(existing_params.keys())

    def discover_parameters(self, url, max_workers=10):
        """Discover parameters using threading"""
        print(f"\n\033[1;33m[SCAN {self.scan_counter}] Starting parameter discovery for: {url}\033[0m")
        print("\033[1;34m" + "─" * 60 + "\033[0m")
        
        existing_params = self.extract_parameters_from_url(url)
        if existing_params:
            print(f"\033[1;35m[INFO] Found existing parameters: {', '.join(existing_params)}\033[0m")
        
        discovered_params = []
        reflective_params = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_param = {
                executor.submit(self.test_parameter, url, param): param 
                for param in self.common_parameters
            }
            
            completed = 0
            total = len(self.common_parameters)
            
            for future in as_completed(future_to_param):
                param = future_to_param[future]
                completed += 1
                
                try:
                    result = future.result()
                    if result:
                        discovered_params.append(result['parameter'])
                        
                        if result['reflected']:
                            reflective_params.append(result['parameter'])
                            print(f"\033[1;32m[✓] [{completed:03d}/{total:03d}] PARAMETER FOUND: {param} (REFLECTED)\033[0m")
                        else:
                            print(f"\033[1;36m[✓] [{completed:03d}/{total:03d}] Parameter found: {param}\033[0m")
                    else:
                        print(f"\033[1;90m[ ] [{completed:03d}/{total:03d}] Testing: {param}\033[0m")
                        
                except Exception as e:
                    print(f"\033[1;31m[!] [{completed:03d}/{total:03d}] Error testing {param}: {str(e)}\033[0m")
        
        # Store results
        self.results[self.scan_counter] = {
            'url': url,
            'discovered': discovered_params,
            'reflective': reflective_params,
            'existing': existing_params,
            'total_tested': total
        }
        
        self.scan_counter += 1
        return discovered_params, reflective_params

    def spider_website(self, start_url, max_pages=20):
        """Spider website to find additional URLs"""
        print(f"\n\033[1;33m[SPIDER] Spidering website: {start_url}\033[0m")
        
        visited = set()
        to_visit = deque([start_url])
        found_urls = []
        
        try:
            while to_visit and len(visited) < max_pages:
                url = to_visit.popleft()
                
                if url in visited:
                    continue
                    
                visited.add(url)
                found_urls.append(url)
                
                try:
                    response = requests.get(url, headers=self.headers, timeout=8, verify=False)
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(url, href)
                        
                        if (full_url.startswith(('http://', 'https://')) and 
                            start_url in full_url and 
                            full_url not in visited):
                            to_visit.append(full_url)
                            
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"\033[1;31m[SPIDER ERROR] {str(e)}\033[0m")
        
        print(f"\033[1;32m[SPIDER] Found {len(found_urls)} URLs\033[0m")
        return found_urls

    def generate_report(self):
        """Generate comprehensive report"""
        print("\n" + "="*80)
        print("\033[1;35m" + "FINAL SCAN REPORT".center(80) + "\033[0m")
        print("="*80)
        
        total_discovered = 0
        total_reflective = 0
        
        for scan_id, data in self.results.items():
            print(f"\n\033[1;36m[SCAN {scan_id}] {data['url']}\033[0m")
            print("\033[1;34m" + "─" * 60 + "\033[0m")
            
            # Existing parameters
            if data['existing']:
                print(f"\033[1;33mExisting parameters ({len(data['existing'])}):\033[0m")
                for i, param in enumerate(data['existing'], 1):
                    print(f"  {i:2d}. {param}")
            
            # Discovered parameters
            if data['discovered']:
                print(f"\n\033[1;32mDiscovered parameters ({len(data['discovered'])}):\033[0m")
                for i, param in enumerate(data['discovered'], 1):
                    status = "🔴 REFLECTIVE" if param in data['reflective'] else "🟢 Normal"
                    print(f"  {i:2d}. {param} - {status}")
            else:
                print(f"\n\033[1;31mNo new parameters discovered\033[0m")
            
            # Reflective parameters
            if data['reflective']:
                print(f"\n\033[1;31mReflective parameters ({len(data['reflective'])}):\033[0m")
                for i, param in enumerate(data['reflective'], 1):
                    print(f"  {i:2d}. {param} - POTENTIAL SECURITY ISSUE")
            
            total_discovered += len(data['discovered'])
            total_reflective += len(data['reflective'])
        
        # Summary
        print("\n" + "="*80)
        print("\033[1;35mSUMMARY REPORT\033[0m")
        print("="*80)
        print(f"\033[1;36mTotal scans performed: {len(self.results)}\033[0m")
        print(f"\033[1;32mTotal parameters discovered: {total_discovered}\033[0m")
        print(f"\033[1;31mTotal reflective parameters: {total_reflective}\033[0m")
        print(f"\033[1;33mTotal parameters tested: {sum(data['total_tested'] for data in self.results.values())}\033[0m")
        
        # Security recommendations
        if total_reflective > 0:
            print(f"\n\033[1;31mSECURITY WARNING: {total_reflective} reflective parameters found!\033[0m")
            print("\033[1;33mThese parameters may be vulnerable to XSS attacks\033[0m")

    def save_results(self, filename):
        """Save results to file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("DarkBoss1BD Parameter Discovery Tool - Results\n")
                f.write("=" * 50 + "\n\n")
                
                for scan_id, data in self.results.items():
                    f.write(f"Scan {scan_id}: {data['url']}\n")
                    f.write(f"Existing Parameters: {', '.join(data['existing'])}\n")
                    f.write(f"Discovered Parameters: {', '.join(data['discovered'])}\n")
                    f.write(f"Reflective Parameters: {', '.join(data['reflective'])}\n")
                    f.write("-" * 50 + "\n")
                
                f.write(f"\nTotal Discovered: {sum(len(data['discovered']) for data in self.results.values())}\n")
                f.write(f"Total Reflective: {sum(len(data['reflective']) for data in self.results.values())}\n")
            
            print(f"\033[1;32m[+] Results saved to: {filename}\033[0m")
        except Exception as e:
            print(f"\033[1;31m[!] Error saving results: {str(e)}\033[0m")

def main():
    # Disable SSL warnings
    requests.packages.urllib3.disable_warnings()
    
    parser = argparse.ArgumentParser(description='DarkBoss1BD Advanced Parameter Discovery Tool')
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-f', '--file', help='File containing list of URLs')
    parser.add_argument('-s', '--spider', action='store_true', help='Spider the website')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('-m', '--max-pages', type=int, default=20, help='Max pages to spider (default: 20)')
    
    args = parser.parse_args()
    
    tool = DarkBossParameterFinder()
    tool.print_banner()
    
    if not args.url and not args.file:
        print("\033[1;31m[!] Error: Please provide a URL or file with URLs\033[0m")
        print("\nUsage examples:")
        print("  python parameter_finder.py -u https://example.com")
        print("  python parameter_finder.py -u https://example.com -s -t 15")
        print("  python parameter_finder.py -f urls.txt -o results.txt")
        sys.exit(1)
    
    targets = []
    
    if args.url:
        try:
            validated_url = tool.validate_url(args.url)
            targets.append(validated_url)
        except ValueError as e:
            print(f"\033[1;31m[!] Error: {str(e)}\033[0m")
            sys.exit(1)
    
    if args.file:
        if os.path.exists(args.file):
            with open(args.file, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        try:
                            validated_url = tool.validate_url(url)
                            targets.append(validated_url)
                        except ValueError:
                            print(f"\033[1;31m[!] Skipping invalid URL: {url}\033[0m")
        else:
            print(f"\033[1;31m[!] Error: File not found: {args.file}\033[0m")
            sys.exit(1)
    
    # Process targets
    for target in targets:
        if args.spider:
            spider_urls = tool.spider_website(target, args.max_pages)
            for url in spider_urls[:5]:  # Limit to first 5 URLs to avoid too many requests
                tool.discover_parameters(url, args.threads)
                time.sleep(1)  # Be polite
        else:
            tool.discover_parameters(target, args.threads)
    
    # Generate report
    tool.generate_report()
    
    # Save results if requested
    if args.output:
        tool.save_results(args.output)
    
    print(f"\n\033[1;35m[+] Scan completed! Thank you for using DarkBoss1BD Tools\033[0m")

if __name__ == "__main__":
    main()
