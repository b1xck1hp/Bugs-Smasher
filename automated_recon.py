#!/usr/bin/env python3
"""
Modular Automated Bug Bounty Tool for Kali Linux

This script is divided into clearly labeled sections so that multiple people
can work on or modify specific parts as needed. It supports individual modules:
    - Subdomain Enumeration (via subfinder, assetfinder, amass, crt.sh, anubis, urlscan, otx)
    - Subdomain Takeover Testing (via nuclei templates and subzy)
    - DNSRecon Integration (via external DNSRecon.sh)
    - Real IP Collection (VirusTotal, AlienVault, urlscan.io)
    - Robots.txt Collection
    - Wayback Machine Path Collection

Each module, when run, outputs its results in a clearly named .txt file (saved in the specified output directory)
so that the output can be used by other tools (e.g., nuclei).

Usage examples:
    Run all modules on a single domain and save outputs:
        ./automated_recon4.py -d example.com -a -o results/
    
    Run only subdomain enumeration on multiple domains from a file:
        ./automated_recon4.py -f domains.txt -s -o results/

If no module-specific flag is provided, the script defaults to --all.
If no domain or file is provided, it prints an array list of available modules and exits.
"""

import argparse
import subprocess
import requests
import sys
import os

# =============================================================================
# Section 1: Global Configuration and Utility Functions
# =============================================================================

# Global configuration
VT_API_KEY = "4ce58c829b95ac6061679b7d117230fc4e2de231007bb9d7f301767920810f7d"
TAKEOVER_FINGERPRINTS = [
    "NoSuchBucket",
    "There isn't a GitHub Pages site here",
    "The specified bucket does not exist",
    "NoSuchHost",
    "NoSuchDomain",
    "The requested URL was not found on this server",
]

def run_command(command):
    """
    Executes a shell command and returns its output as a string.
    On error, prints a message with the command that failed.
    """
    try:
        result = subprocess.run(
            command, shell=True, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {command}\nError: {e.stderr.strip()}", file=sys.stderr)
        return ""

# =============================================================================
# Section 2: Subdomain Enumeration Functions
# =============================================================================

def enumerate_subdomains(domain):
    """
    Enumerates subdomains for a given domain using multiple tools.
    Returns a list of unique subdomains.
    """
    print(f"\n[+] Starting subdomain enumeration for: {domain}")
    subdomains = set()

    commands = {
        "subfinder": f"subfinder -d {domain} -silent",
        "assetfinder": f"assetfinder --subs-only {domain}",
        "amass": f"amass enum -d {domain} -quiet",
        "crt": f'''curl -s "https://crt.sh/?q=%25.{domain}&output=json" | jq -r '.[].name_value' | sed 's/\\n/\n/g' | sort -u''',
        "anubis": f'''curl -sk "https://jldc.me/anubis/subdomains/{domain}" | awk -F'"' '{{for(i=2;i<NF;i+=2) print $i}}' | sort -u''',
        "urlscan": f'''curl -sk "https://urlscan.io/api/v1/search/?q={domain}" | jq -r '.results[].task.domain' | grep -E "\\.{domain}$" | sort -u''',
        "otx": f'''curl -sk "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns" | jq -r '.passive_dns[].hostname' | grep -E "\\.{domain}$" | sort -u'''
    }

    for tool, cmd in commands.items():
        print(f"[+] Running {tool} command...")
        output = run_command(cmd)
        if output:
            new_subs = set(output.splitlines())
            subdomains.update(new_subs)
            print(f"[+] {tool} found {len(new_subs)} subdomains.")
        else:
            print(f"[!] {tool} returned no output or failed.")
    print(f"[+] Total unique subdomains found: {len(subdomains)}")
    return list(subdomains)

# =============================================================================
# Section 3: Subdomain Takeover Testing Functions
# =============================================================================

def test_subdomain_takeover_nuclei(subdomains_file):
    """
    Tests subdomains for takeover using nuclei templates
    """
    print("\n[+] Testing for subdomain takeover using nuclei...")
    cmd = f"nuclei -t ~/nuclei-templates/http/takeovers -l {subdomains_file}"
    output = run_command(cmd)
    return output

def test_subdomain_takeover_subzy(subdomains_file):
    """
    Tests subdomains for takeover using subzy
    """
    print("\n[+] Testing for subdomain takeover using subzy...")
    cmd = f"subzy run --targets {subdomains_file} --hide_fails --vuln | grep -v -E 'Akamai|xyz|available|-'"
    output = run_command(cmd)
    return output

def check_takeover_vulnerabilities(subdomains, takeover_method="both"):
    """
    Checks subdomains for potential takeover vulnerabilities using specified method(s).
    takeover_method can be "nuclei", "subzy", or "both"
    """
    print("\n[+] Starting subdomain takeover checks...")
    
    # Write subdomains to temporary file
    temp_file = "temp_subdomains.txt"
    with open(temp_file, "w") as f:
        for subdomain in subdomains:
            f.write(f"{subdomain}\n")

    results = []
    
    try:
        if takeover_method in ["nuclei", "both"]:
            nuclei_results = test_subdomain_takeover_nuclei(temp_file)
            if nuclei_results:
                results.append(("nuclei", nuclei_results))
                
        if takeover_method in ["subzy", "both"]:
            subzy_results = test_subdomain_takeover_subzy(temp_file)
            if subzy_results:
                results.append(("subzy", subzy_results))
                
    finally:
        # Clean up temporary file
        if os.path.exists(temp_file):
            os.remove(temp_file)
            
    return results

# =============================================================================
# Section 4: Port Scanning Functions
# =============================================================================

def perform_port_scan(target, scan_type="default"):
    """
    Performs port scanning using nmap with different scan types.
    scan_type options:
        - default: Common ports TCP scan (-sT -p-)
        - quick: Top 1000 ports (-F)
        - comprehensive: All ports TCP/UDP (-sT -sU -p-)
        - stealth: Stealth SYN scan (-sS -p-)
    """
    print(f"\n[+] Starting port scan for: {target}")
    
    scan_commands = {
        "default": f"nmap -sT -p- -T4 --min-rate 1000 {target}",
        "quick": f"nmap -F -T4 {target}",
        "comprehensive": f"nmap -sT -sU -p- -T4 --min-rate 1000 {target}",
        "stealth": f"nmap -sS -p- -T4 --min-rate 1000 {target}"
    }
    
    cmd = scan_commands.get(scan_type, scan_commands["default"])
    print(f"[+] Running scan command: {cmd}")
    
    output = run_command(cmd)
    if output:
        print(f"[+] Port scan completed for {target}")
        return output
    else:
        print(f"[!] Port scan failed for {target}")
        return ""

def scan_ports(targets, scan_type="default"):
    """
    Handles port scanning for multiple targets.
    Returns a dictionary with scan results for each target.
    """
    results = {}
    for target in targets:
        print(f"\n[+] Processing port scan for: {target}")
        scan_result = perform_port_scan(target, scan_type)
        results[target] = scan_result
    return results

# =============================================================================
# Section 5: Real IP Collection Functions
# =============================================================================

def get_ips_virustotal(domain):
    print(f"\n[+] Querying VirusTotal for {domain}...")
    url = f"https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}&apikey={VT_API_KEY}"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        ips = set()
        def extract_ips(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == "ip_address" and isinstance(v, str):
                        ips.add(v)
                    else:
                        extract_ips(v)
            elif isinstance(obj, list):
                for item in obj:
                    extract_ips(item)
        extract_ips(data)
        print(f"[+] VirusTotal found {len(ips)} IP addresses.")
        return list(ips)
    except Exception as e:
        print(f"[!] VirusTotal query failed for {domain}: {e}", file=sys.stderr)
        return []

def get_ips_alienvault(domain):
    print(f"\n[+] Querying AlienVault OTX for {domain}...")
    url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list?limit=500&page=1"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        ips = set()
        for item in data.get("url_list", []):
            ip = item.get("result", {}).get("urlworker", {}).get("ip", "")
            if ip:
                ips.add(ip)
        print(f"[+] AlienVault OTX found {len(ips)} IP addresses.")
        return list(ips)
    except Exception as e:
        print(f"[!] AlienVault query failed for {domain}: {e}", file=sys.stderr)
        return []

def get_ips_urlscan(domain):
    print(f"\n[+] Querying urlscan.io for {domain}...")
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        ips = set()
        for result in data.get("results", []):
            ip = result.get("page", {}).get("ip", "")
            if ip:
                ips.add(ip)
        print(f"[+] urlscan.io found {len(ips)} IP addresses.")
        return list(ips)
    except Exception as e:
        print(f"[!] urlscan.io query failed for {domain}: {e}", file=sys.stderr)
        return []

def get_real_ips_dns(domain):
    """
    Gets real IPs from DNS A records and filters out CDN/WAF IPs using httpx-toolkit.
    Also checks VirusTotal, AlienVault OTX and urlscan.io for additional IPs.
    """
    print(f"\n[+] Getting DNS A records for {domain}...")
    
    # Get A records using dnsrecon
    cmd = f"dnsrecon -d {domain} -t std | grep -E '^[*].*A {domain}'"
    output = run_command(cmd)
    
    ips = set()
    
    # Extract IPs from dnsrecon output
    if output:
        for line in output.splitlines():
            ip = line.strip().split()[-1]
            if ip and ip[0].isdigit():  # Basic IP validation
                ips.add(ip)
    
    # Get IPs from VirusTotal
    cmd = f'curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}&apikey=6cd43bdc09bfb3a38d58f607cac9c908a2bdd66ea4c5a85b4a5db4cc88b4e3ea" | jq -r \'.domain_siblings[]\''
    vt_output = run_command(cmd)
    if vt_output:
        for line in vt_output.splitlines():
            if line and line[0].isdigit():
                ips.add(line)
                
    # Fixed AlienVault command using raw string for the grep pattern
    cmd = f'''curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list?limit=500&page=1" | jq -r '.url_list[]?.result?.urlworker?.ip // empty' | grep -Eo {r'"([0-9]{1,3}\.?){4}"'} | httpx-toolkit -sc -td -title'''
    av_output = run_command(cmd)
    if av_output:
        for line in av_output.splitlines():
            if line and line[0].isdigit():
                ips.add(line)

    # Fixed urlscan.io command using raw string for the grep pattern
    cmd = f'''curl -s "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000" | jq -r '.results[]?.page?.ip // empty' | grep -Eo {r'"([0-9]{1,3}\.?){4}"'} | httpx-toolkit -sc -td -title -server'''
    us_output = run_command(cmd)
    if us_output:
        for line in us_output.splitlines():
            if line and line[0].isdigit():
                ips.add(line)

    if not ips:
        print("[!] No valid IPs found from any source")
        return []
    
    print(f"[+] Found {len(ips)} unique IP addresses, checking for CDN/WAF...")
    
    # Check each IP with httpx-toolkit
    real_ips = []
    for ip in ips:
        cmd = f"echo 'http://{ip}' | httpx -silent -response-in-json"
        output = run_command(cmd)
        
        # Skip if no output or contains CDN/WAF indicators
        if not output or any(cdn in output.lower() for cdn in ["cloudflare", "akamai", "fastly", "incapsula", "sucuri"]):
            continue
        
        real_ips.append(ip)
    
    print(f"[+] Found {len(real_ips)} real IPs after filtering CDN/WAF")
    return real_ips

def collect_real_ips(domain):
    """
    Aggregates IP addresses for a domain from multiple sources.
    Returns a dictionary with the results.
    """
    ips = {
        "DNS": get_real_ips_dns(domain),
        "VirusTotal": get_ips_virustotal(domain),
        "AlienVault": get_ips_alienvault(domain),
        "urlscan": get_ips_urlscan(domain)
    }
    return ips

# =============================================================================
# Section 6: Robots.txt Collection Function
# =============================================================================

def collect_robots(domain):
    """
    Retrieves the robots.txt file for a domain using robofinder.
    """
    print(f"\n[+] Retrieving robots.txt for {domain} ...")
    cmd = f"robofinder -u https://{domain}"
    output = run_command(cmd)
    if output:
        print(f"[+] robots.txt content retrieved for {domain}.")
    else:
        print(f"[!] No robots.txt found for {domain} or an error occurred.")
    return output

# =============================================================================
# Section 7: Wayback Machine Collection Function
# =============================================================================

def collect_wayback_paths(domain):
    """
    Retrieves archived URLs/paths for a domain from the Wayback Machine.
    """
    print(f"\n[+] Querying Wayback Machine for paths related to {domain} ...")
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&fl=original&collapse=urlkey"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        paths = list(set(resp.text.strip().splitlines()))
        print(f"[+] Wayback Machine returned {len(paths)} paths for {domain}.")
        return paths
    except Exception as e:
        print(f"[!] Wayback Machine query failed for {domain}: {e}", file=sys.stderr)
        return []

# =============================================================================
# Section 8: Main Processing and Argument Parsing Functions
# =============================================================================

def parse_arguments():
    """
    Parses command-line arguments and returns them.
    If no domain or file is provided, displays available modules and help.
    """
    parser = argparse.ArgumentParser(
        description="Modular Automated Recon Tool for Kali Linux"
    )
    # Domain input options (not required—if none provided, we show available modules)
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-d", "--domain", help="Target domain (e.g., example.com)")
    group.add_argument("-f", "--file", help="File with target domains (one per line)")
    # Module selection options with shortcuts:
    parser.add_argument("-a", "--all", action="store_true", help="Run all modules (default if no module is specified)")
    parser.add_argument("-s", "--subdomains", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("-t", "--takeover", action="store_true", help="Run subdomain takeover testing")
    parser.add_argument("-i", "--realips", action="store_true", help="Run real IP collection")
    parser.add_argument("-r", "--robots", action="store_true", help="Run robots.txt collection")
    parser.add_argument("-w", "--wayback", action="store_true", help="Run Wayback Machine path collection")
    # Takeover method selection
    parser.add_argument("--takeover-method", choices=["nuclei", "subzy", "both"], default="both",
                      help="Select takeover scanning method (default: both)")
    # Output directory option
    parser.add_argument("-o", "--output", help="Directory to save results", default="results")
    # Add port scanning arguments
    parser.add_argument("-p", "--ports", action="store_true", help="Run port scanning")
    parser.add_argument("--scan-type", choices=["default", "quick", "comprehensive", "stealth"],
                      default="default", help="Select port scanning type (default: default)")
    args = parser.parse_args()

    if not args.domain and not args.file:
        print("\nAvailable modules and shortcuts:")
        print("  -a, --all         : Run all modules")
        print("  -s, --subdomains  : Run subdomain enumeration")
        print("  -t, --takeover    : Run subdomain takeover testing")
        print("  -i, --realips     : Run real IP collection")
        print("  -r, --robots      : Run robots.txt collection")
        print("  -w, --wayback     : Run Wayback Machine path collection")
        print("\nTakeover scanning methods:")
        print("  --takeover-method : Select 'nuclei', 'subzy', or 'both' (default)")
        print("\nPlease provide a target domain (-d) or a file (-f) with target domains.")
        parser.print_help()
        exit(0)
    return args

def process_domain(domain, modules):
    """
    Processes a single domain based on selected modules.
    Returns a dictionary containing the results.
    """
    results = {"domain": domain}

    # Module: Subdomain Enumeration
    if modules.get("subdomains"):
        results["subdomains"] = enumerate_subdomains(domain)
    else:
        results["subdomains"] = []

    # Module: Subdomain Takeover Testing (requires subdomains)
    if modules.get("takeover"):
        if not results["subdomains"]:
            print("[!] No subdomains available for takeover testing.")
            results["takeover_vulnerabilities"] = []
        else:
            results["takeover_vulnerabilities"] = check_takeover_vulnerabilities(
                results["subdomains"], 
                modules.get("takeover_method", "both")
            )
    else:
        results["takeover_vulnerabilities"] = []

    # Module: Real IP Collection
    if modules.get("realips"):
        results["real_ips"] = collect_real_ips(domain)
    else:
        results["real_ips"] = {}

    # Module: Robots.txt Collection (for base domain and subdomains)
    if modules.get("robots"):
        robots_collection = {}
        domains_to_check = [domain] + results.get("subdomains", [])
        for d in domains_to_check:
            robots_content = collect_robots(d)
            robots_collection[d] = robots_content if robots_content else "No robots.txt found or error occurred."
        results["robots_txt"] = robots_collection
    else:
        results["robots_txt"] = {}

    # Module: Wayback Machine Path Collection (for base domain and subdomains)
    if modules.get("wayback"):
        wayback_collection = {}
        domains_to_check = [domain] + results.get("subdomains", [])
        for d in domains_to_check:
            paths = collect_wayback_paths(d)
            wayback_collection[d] = "\n".join(paths) if paths else "No Wayback Machine paths found or error occurred."
        results["wayback_paths"] = wayback_collection
    else:
        results["wayback_paths"] = {}

    # Module: Port Scanning
    if modules.get("ports"):
        results["port_scan"] = scan_ports([domain], modules.get("scan_type", "default"))
    else:
        results["port_scan"] = {}

    return results

def save_results(domain, results, output_dir, modules):
    """
    Saves results for a domain into separate .txt files in the specified output directory.
    Files are named clearly for each module.
    """
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    base_filename = os.path.join(output_dir, domain.replace(".", "_"))
    
    # Save subdomains
    if modules.get("subdomains"):
        with open(f"{base_filename}_subdomains.txt", "w") as f:
            if results.get("subdomains"):
                for sub in results["subdomains"]:
                    f.write(f"{sub}\n")
            else:
                f.write("No subdomains found.\n")
        print(f"[+] Subdomains saved to {base_filename}_subdomains.txt")
    
    # Save takeover vulnerabilities
    if modules.get("takeover"):
        with open(f"{base_filename}_takeover.txt", "w") as f:
            if results.get("takeover_vulnerabilities"):
                for tool, findings in results["takeover_vulnerabilities"]:
                    f.write(f"\n=== Results from {tool} ===\n")
                    f.write(findings + "\n")
            else:
                f.write("No takeover vulnerabilities found.\n")
        print(f"[+] Takeover vulnerabilities saved to {base_filename}_takeover.txt")
    
    # Save Real IPs
    if modules.get("realips"):
        with open(f"{base_filename}_realips.txt", "w") as f:
            if results.get("real_ips"):
                for source, ips in results["real_ips"].items():
                    if ips:  # Only write non-empty results
                        f.write(f"=== {source} ===\n")
                        for ip in ips:
                            f.write(f"{ip}\n")
                        f.write("\n")
            else:
                f.write("No real IPs found.\n")
        print(f"[+] Real IPs saved to {base_filename}_realips.txt")
    
    # Save Robots.txt results
    if modules.get("robots"):
        with open(f"{base_filename}_robots.txt", "w") as f:
            if results.get("robots_txt"):
                for d, content in results["robots_txt"].items():
                    f.write(f"--- {d} ---\n")
                    f.write(content + "\n")
            else:
                f.write("No robots.txt found.\n")
        print(f"[+] Robots.txt output saved to {base_filename}_robots.txt")
    
    # Save Wayback paths
    if modules.get("wayback"):
        with open(f"{base_filename}_wayback.txt", "w") as f:
            if results.get("wayback_paths"):
                for d, paths in results["wayback_paths"].items():
                    f.write(f"--- {d} ---\n")
                    f.write(paths + "\n")
            else:
                f.write("No Wayback Machine paths found.\n")
        print(f"[+] Wayback Machine paths saved to {base_filename}_wayback.txt")

    # Save Port Scan results
    if modules.get("ports"):
        with open(f"{base_filename}_nmap.txt", "w") as f:
            if results.get("port_scan"):
                for target, scan_output in results["port_scan"].items():
                    f.write(f"=== Port Scan Results for {target} ===\n")
                    f.write(scan_output + "\n\n")
            else:
                f.write("No port scan results found.\n")
        print(f"[+] Port scan results saved to {base_filename}_nmap.txt")

def main():
    args = parse_arguments()

    # Determine selected modules; if none specified, default to all.
    modules = {
        "subdomains": args.all or args.subdomains,
        "takeover": args.all or args.takeover,
        "realips": args.all or args.realips,
        "robots": args.all or args.robots,
        "wayback": args.all or args.wayback,
        "ports": args.all or args.ports,
        "takeover_method": args.takeover_method,
        "scan_type": args.scan_type
    }
    if not any([args.all, args.subdomains, args.takeover, args.realips, args.robots, args.wayback, args.ports]):
        for key in modules:
            if key != "takeover_method" and key != "scan_type":
                modules[key] = True

    # Collect domains from file or single domain.
    if args.domain:
        targets = [args.domain.strip()]
    else:
        try:
            with open(args.file, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Could not read file {args.file}: {e}", file=sys.stderr)
            sys.exit(1)

    all_results = {}
    for target in targets:
        print("\n" + "=" * 60)
        print(f"[*] Processing target: {target}")
        result = process_domain(target, modules)
        all_results[target] = result
        save_results(target, result, args.output, modules)

    # Print final summary to stdout
    print("\n" + "=" * 60)
    print("[*] Final Recon Results:")
    for domain, data in all_results.items():
        print(f"\nDomain: {domain}")
        print("-" * 40)
        if modules["subdomains"]:
            print("Subdomains:")
            for sub in data.get("subdomains", []):
                print(f"  - {sub}")
        if modules["takeover"]:
            print("\nPotential Subdomain Takeover Vulnerabilities:")
            for tool, findings in data.get("takeover_vulnerabilities", []):
                print(f"\n=== Results from {tool} ===")
                print(findings)
        if modules["realips"]:
            print("\nReal IPs Collected:")
            for source, ips in data.get("real_ips", {}).items():
                print(f"  {source}: {', '.join(ips) if ips else 'None'}")
        if modules["robots"]:
            print("\nRobots.txt Content:")
            for d, content in data.get("robots_txt", {}).items():
                print(f"--- {d} ---")
                print(content if content else "No robots.txt found")
        if modules["wayback"]:
            print("\nWayback Machine Paths:")
            for d, paths in data.get("wayback_paths", {}).items():
                print(f"--- {d} ---")
                print(paths)
        if modules["ports"]:
            print("\nPort Scan Results:")
            for target, scan_output in data.get("port_scan", {}).items():
                print(f"--- {target} ---")
                print(scan_output)
        print("=" * 60)

if __name__ == "__main__":
    # Suppress insecure request warnings if needed.
    requests.packages.urllib3.disable_warnings()
    main()
