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
                if key in ["YOUR_VT_API_KEY_HERE", "YOUR_API_KEY", "YOUR_VT_API_KEY"] or not key:
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


def identify_hash_type(file_hash: str) -> str:
    """Validate and identify hash type based on length."""
    file_hash = file_hash.strip().lower()
    length = len(file_hash)
    if length == 32:
        return "MD5"
    elif length == 40:
        return "SHA-1"
    elif length == 64:
        return "SHA-256"
    return "UNKNOWN"


def check_hash(file_hash: str):
    """Query VirusTotal API v3 for an individual hash, including digital signature details."""
    if not VT_API_KEY:
        return "ERROR", f"[MISSING API KEY] {file_hash} (Check config/config.txt)"

    file_hash = file_hash.strip().lower()
    hash_type = identify_hash_type(file_hash)

    if hash_type == "UNKNOWN":
        return "ERROR", f"[-] Invalid hash format: {file_hash}"

    url = f"{BASE_URL}/files/{file_hash}"
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

            # Extract Signature Information if available
            sig_info = attributes.get("signature_info", {})
            verified_status = sig_info.get("verified", "Not Signed / Unavailable")
            signers = sig_info.get("signers", "N/A")
            issuer = sig_info.get("cert issuer", "N/A")

            link = f"https://www.virustotal.com/gui/file/{file_hash}"

            # Format signature details string
            sig_details = f" | Signed: {verified_status}"
            if verified_status not in ["Not Signed / Unavailable", "Unsigned", "N/A"]:
                sig_details += f" (Signer: {signers} | Issuer: {issuer})"

            if malicious > 0 or suspicious > 0:
                return (
                    "UNSAFE",
                    f"[UNSAFE] {file_hash} | Malicious: {malicious}, Suspicious: {suspicious}{sig_details} | {link}",
                )
            else:
                return (
                    "SAFE",
                    f"[SAFE]   {file_hash} | Harmless: {harmless}{sig_details} | {link}",
                )

        elif response.status_code == 404:
            return "NOT_FOUND", f"[NOT FOUND] {file_hash} (Never submitted to VT)"
        elif response.status_code == 401:
            return "ERROR", f"[UNAUTHORIZED] {file_hash} (Invalid API key in config/config.txt)"
        elif response.status_code == 429:
            return "ERROR", f"[RATE LIMIT] {file_hash} (Hit 429 Too Many Requests)"
        else:
            return "ERROR", f"[ERROR {response.status_code}] {file_hash}: {response.text}"

    except requests.exceptions.RequestException as e:
        return "ERROR", f"[NETWORK ERROR] {file_hash}: {e}"


def main():
    print(Fore.CYAN + "=== VirusTotal Hash & Signature Reputation Checker ===")
    
    if not VT_API_KEY:
        print(Fore.RED + "[-] Cannot proceed without a valid VirusTotal API key in config/config.txt.")
        sys.exit(1)

    # Prompt user to paste comma-separated hashes
    raw_input_data = input("Please paste the hashes (separated by commas) and press enter:\n> ")

    # Split by comma, strip whitespace, and filter out empty entries
    hashes = [h.strip() for h in raw_input_data.split(",") if h.strip()]

    if not hashes:
        print(Fore.YELLOW + "[-] No valid hashes provided. Exiting.")
        sys.exit(1)

    total_hashes = len(hashes)
    print(f"\n[*] Loaded {total_hashes} hash(es). Starting analysis...\n")

    results = []

    for count, h in enumerate(hashes, start=1):
        status, message = check_hash(h)
        results.append((status, message))
        update_progress(count, total_hashes, f"Checking: {h[:10]}...")

        # If 4 lookups are completed and there are still items left, pause for 60 seconds with countdown
        if count % 4 == 0 and count < total_hashes:
            print("\n")
            print(f"[*] Batch of 4 complete. Pausing for 60 seconds to respect rate limits...")
            for remaining in range(60, 0, -1):
                sys.stdout.write(f"\r[!] Resuming in {remaining:2d} seconds... ")
                sys.stdout.flush()
                time.sleep(1)
            print("\r[+] Resuming lookups...                                        ")

    print("\n\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70 + "\n")

    safe_count = 0
    unsafe_count = 0
    error_count = 0
    not_found_count = 0

    for status, message in results:
        if status == "SAFE":
            safe_count += 1
            print(Fore.GREEN + message)
        elif status == "UNSAFE":
            unsafe_count += 1
            print(Fore.RED + message)
        elif status == "NOT_FOUND":
            not_found_count += 1
            print(Fore.CYAN + message)
        else:
            error_count += 1
            print(Fore.YELLOW + message)

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    print(Fore.GREEN + f"Safe Hashes     : {safe_count}")
    print(Fore.RED + f"Unsafe Hashes   : {unsafe_count}")
    print(Fore.CYAN + f"Not Found on VT : {not_found_count}")

    if error_count:
        print(Fore.YELLOW + f"Errors / Limits : {error_count}")

    print("=" * 70)


if __name__ == "__main__":
    main()
