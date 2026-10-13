import os
import re
import sys
import time
import requests
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)


def load_vt_api_key():
    """Reads and parses the VirusTotal API key from config/config.txt."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, "config", "config.txt")

    if not os.path.exists(config_path):
        print(Fore.RED + f"[!] Error: Configuration file not found at {config_path}")
        print(Fore.YELLOW + "[!] Please ensure 'config/config.txt' exists.")
        return None

    try:
        with open(config_path, "r", encoding="utf-8") as file:
            content = file.read()
            
            # Match formats like: Your_Virus_Total_API_Key = "KEY" or VT_API_KEY = "KEY"
            match = re.search(r'(?:Your_Virus_Total_API_Key|VT_API_KEY)\s*=\s*["\']([^"\']+)["\']', content)
            if match:
                key = match.group(1).strip()
                if key in ["YOUR_VT_API_KEY_HERE", "YOUR_API_KEY"] or not key:
                    print(Fore.YELLOW + f"[!] Warning: API key in {config_path} is set to default/placeholder.")
                    return None
                return key
            
            # Fallback for plain-text keys on a single line (ignoring comments)
            lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
            if lines:
                return lines[0].strip('"\'')

            print(Fore.RED + f"[!] Error: Could not parse API key from {config_path}")
            return None

    except Exception as e:
        print(Fore.RED + f"[!] Error reading config file: {e}")
        return None


# Load the API Key from config/config.txt
VT_API_KEY = load_vt_api_key()
BASE_URL = "https://www.virustotal.com/api/v3"


def update_progress(current, total, status_text=""):
    """Displays a dynamic progress bar in the terminal."""
    bar_length = 30
    percent = float(current) / total
    arrow = "-" * max(0, int(round(percent * bar_length) - 1)) + ">"
    spaces = " " * max(0, bar_length - len(arrow))
    sys.stdout.write(
        f"\rProgress: [{arrow + spaces}] {int(percent * 100)}% ({current}/{total}) {status_text:<25}"
    )
    sys.stdout.flush()


def check_domain(domain: str):
    """Query VirusTotal API v3 for domain reputation and attributes."""
    if not VT_API_KEY:
        return "ERROR", "Status       : [MISSING VT API KEY IN CONFIG]"

    domain = domain.strip().lower()
    if not domain:
        return "ERROR", "[-] Empty domain provided."

    url = f"{BASE_URL}/domains/{domain}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            registrar = attributes.get("registrar", "N/A")
            link = f"https://www.virustotal.com/gui/domain/{domain}"

            threat_status = "[UNSAFE / MALICIOUS]" if (malicious > 0 or suspicious > 0) else "[CLEAN / SAFE]"

            details = (
                f"Status       : {threat_status}\n"
                f"Malicious    : {malicious}\n"
                f"Suspicious   : {suspicious}\n"
                f"Harmless     : {harmless}\n"
                f"Undetected   : {undetected}\n"
                f"Registrar    : {registrar}\n"
                f"VT Link      : {link}"
            )

            status_label = "UNSAFE" if (malicious > 0 or suspicious > 0) else "SAFE"
            return status_label, details

        elif response.status_code == 404:
            return "NOT_FOUND", f"Status       : [NOT FOUND ON VIRUSTOTAL]"
        elif response.status_code == 401:
            return "ERROR", f"Status       : [UNAUTHORIZED - INVALID API KEY]"
        elif response.status_code == 429:
            return "ERROR", f"Status       : [RATE LIMIT HIT (429)]"
        else:
            return "ERROR", f"Status       : [API ERROR {response.status_code}]"

    except requests.exceptions.RequestException as e:
        return "ERROR", f"Status       : [NETWORK EXCEPTION: {e}]"


def main():
    print(Fore.CYAN + "=== VirusTotal Domain Reputation Scanner ===")

    if not VT_API_KEY:
        print(Fore.RED + "[-] Cannot proceed without a valid VirusTotal API key in config/config.txt.")
        sys.exit(1)

    raw_input_data = input("Please paste the domains (separated by commas) and press enter:\n> ")
    domains = [d.strip() for d in raw_input_data.split(",") if d.strip()]

    if not domains:
        print(Fore.YELLOW + "[-] No valid domains provided. Exiting.")
        sys.exit(1)

    total_domains = len(domains)
    print(f"\n[*] Loaded {total_domains} domain(s). Starting analysis...\n")

    results = []

    for count, domain in enumerate(domains, start=1):
        status, message = check_domain(domain)
        results.append((domain, status, message))
        update_progress(count, total_domains, f"Checking: {domain[:15]}...")

        # Rate-limit management: pause after every 4 requests to comply with VT free tier
        if count % 4 == 0 and count < total_domains:
            print("\n")
            print(f"[*] Batch of 4 complete. Pausing for 60 seconds to respect rate limits...")
            for remaining in range(60, 0, -1):
                sys.stdout.write(f"\r[!] Resuming in {remaining:2d} seconds... ")
                sys.stdout.flush()
                time.sleep(1)
            print("\r[+] Resuming scans...                                        ")

    # Output block layout
    print("\n\n" + "=" * 50)
    print("Domain Scan Info")
    print("================")

    for domain, status, details in results:
        print(f"\nDomain: {domain}")
        print("-" * len(f"Domain: {domain}"))

        if status == "SAFE":
            print(Fore.GREEN + details)
        elif status == "UNSAFE":
            print(Fore.RED + details)
        else:
            print(Fore.YELLOW + details)
        print()


if __name__ == "__main__":
    main()
