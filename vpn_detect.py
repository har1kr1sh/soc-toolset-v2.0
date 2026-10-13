import os
import re
import sys
import time
import requests
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)


def load_proxycheck_api_key():
    """Reads and parses the ProxyCheck API key from config/config.txt."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, "config", "config.txt")

    if not os.path.exists(config_path):
        print(Fore.YELLOW + f"[!] Warning: Configuration file not found at {config_path}")
        print(Fore.YELLOW + "[!] Running without ProxyCheck API key (free tier limits apply).")
        return ""

    try:
        with open(config_path, "r", encoding="utf-8") as file:
            content = file.read()
            
            # Match formats like: Your_ProxyCheck_API_Key = "KEY" or PROXYCHECK_API_KEY = "KEY"
            match = re.search(r'(?:Your_ProxyCheck_API_Key|PROXYCHECK_API_KEY)\s*=\s*["\']([^"\']*)["\']', content)
            if match:
                key = match.group(1).strip()
                if key in ["YOUR_PROXYCHECK_API_KEY_HERE", "YOUR_API_KEY", "your api key"] or not key:
                    return ""
                return key
            
            return ""

    except Exception as e:
        print(Fore.RED + f"[!] Error reading config file: {e}")
        return ""


# Load the API Key dynamically from config/config.txt
PROXYCHECK_API_KEY = load_proxycheck_api_key()


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


def check_ip(ip: str):
    """Query ProxyCheck.io API v3 for an individual IP address and extract full metadata dictionaries."""
    ip = ip.strip()
    if not ip:
        return "ERROR", "[-] Empty IP address provided."

    # Build URL dynamically depending on whether an API key is present
    if PROXYCHECK_API_KEY:
        url = f"https://proxycheck.io/v3/{ip}?key={PROXYCHECK_API_KEY}&vpn=1"
    else:
        url = f"https://proxycheck.io/v3/{ip}?vpn=1"

    try:
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "ok":
                ip_data = data.get(ip, {})
                
                is_proxy = ip_data.get("proxy", False)
                is_vpn = ip_data.get("vpn", False)
                
                # Network Details
                net = ip_data.get("network", {}) or {}
                asn = net.get("asn", "N/A")
                ip_range = net.get("range", "N/A")
                hostname = net.get("hostname", "N/A")
                provider = net.get("provider", "Unknown Provider")
                organisation = net.get("organisation", "Unknown Org")
                conn_type = net.get("type", "Unknown")

                # Location Details
                loc = ip_data.get("location", {}) or {}
                continent_name = loc.get("continent_name", "N/A")
                continent_code = loc.get("continent_code", "N/A")
                country_name = loc.get("country_name", "Unknown Country")
                country_code = loc.get("country_code", "N/A")
                region_name = loc.get("region_name", "N/A")
                region_code = loc.get("region_code", "N/A")
                city_name = loc.get("city_name", "N/A")
                postal_code = loc.get("postal_code", "N/A")
                latitude = loc.get("latitude", "N/A")
                longitude = loc.get("longitude", "N/A")
                timezone = loc.get("timezone", "N/A")
                
                curr = loc.get("currency", {}) or {}
                curr_name = curr.get("name", "N/A")
                curr_code = curr.get("code", "N/A")
                curr_symbol = curr.get("symbol", "")

                threat_status = "[VPN / PROXY DETECTED]" if (is_proxy or is_vpn) else "[CLEAN / RESIDENTIAL]"

                # Format structured output per IP
                details = (
                    f"Status       : {threat_status}\n"
                    f"asn          : {asn}\n"
                    f"range        : {ip_range}\n"
                    f"hostname     : {hostname}\n"
                    f"provider     : {provider}\n"
                    f"organisation : {organisation}\n"
                    f"type         : {conn_type}\n"
                    f"continent_name: {continent_name}\n"
                    f"continent_code: {continent_code}\n"
                    f"country_name : {country_name}\n"
                    f"country_code : {country_code}\n"
                    f"region_name  : {region_name}\n"
                    f"region_code  : {region_code}\n"
                    f"city_name    : {city_name}\n"
                    f"postal_code  : {postal_code}\n"
                    f"latitude     : {latitude}\n"
                    f"longitude    : {longitude}\n"
                    f"timezone     : {timezone}\n"
                    f"currency     : Name: {curr_name}, Code: {curr_code}, Symbol: {curr_symbol}"
                )

                status_label = "UNSAFE" if (is_proxy or is_vpn) else "SAFE"
                return status_label, details
            else:
                msg = data.get("message", "Unknown API error")
                return "ERROR", f"API Error: {msg}"
        else:
            return "ERROR", f"HTTP Error Status {response.status_code}"

    except requests.exceptions.RequestException as e:
        return "ERROR", f"Network Exception: {e}"


def main():
    print(Fore.CYAN + "=== ProxyCheck.io IP Intelligence Tool ===")
    
    raw_input_data = input("Please paste the IP addresses (separated by commas) and press enter:\n> ")
    ips = [ip.strip() for ip in raw_input_data.split(",") if ip.strip()]

    if not ips:
        print(Fore.YELLOW + "[-] No valid IP addresses provided. Exiting.")
        sys.exit(1)

    total_ips = len(ips)
    print(f"\n[*] Loaded {total_ips} IP(s). Starting analysis...\n")

    results = []

    for count, ip in enumerate(ips, start=1):
        status, message = check_ip(ip)
        results.append((ip, status, message))
        update_progress(count, total_ips, f"Checking: {ip[:15]}...")
        
        if count < total_ips:
            time.sleep(0.2)

    # Print requested block layout format
    print("\n\n" + "=" * 50)
    print("VPN Detect Info")
    print("==============")

    for ip, status, details in results:
        print(f"\nIP: {ip}")
        print("-" * len(f"IP: {ip}"))
        
        if status == "SAFE":
            print(Fore.GREEN + details)
        elif status == "UNSAFE":
            print(Fore.RED + details)
        else:
            print(Fore.YELLOW + details)
        print()


if __name__ == "__main__":
    main()
