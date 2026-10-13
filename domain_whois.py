import sys
import time
import whois
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)


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


def clean_field(val):
    """Helper to handle lists or single string values returned by the whois library."""
    if isinstance(val, list):
        # Format list elements cleanly if multiple entries exist
        cleaned = [str(v).strip() for v in val if v]
        return ", ".join(cleaned) if cleaned else "N/A"
    return str(val).strip() if val else "N/A"


def perform_whois(domain: str):
    """Query WHOIS records for an individual domain."""
    domain = domain.strip().lower()
    if not domain:
        return "ERROR", "[-] Empty domain provided."

    try:
        w = whois.whois(domain)
        if not w or not w.domain_name:
            return "ERROR", "Status         : [WHOIS RECORD NOT FOUND]"

        registrar = clean_field(w.registrar)
        creation_date = clean_field(w.creation_date)
        expiration_date = clean_field(w.expiration_date)
        updated_date = clean_field(w.updated_date)
        emails = clean_field(w.emails)
        name_servers = clean_field(w.name_servers)

        details = (
            f"Status         : [SUCCESS]\n"
            f"registrar      : {registrar}\n"
            f"creation_date  : {creation_date}\n"
            f"expiration_date: {expiration_date}\n"
            f"updated_date   : {updated_date}\n"
            f"emails         : {emails}\n"
            f"name_servers   : {name_servers}"
        )
        return "SUCCESS", details

    except Exception as e:
        return "ERROR", f"Status         : [WHOIS LOOKUP FAILED: {str(e)}]"


def main():
    print(Fore.CYAN + "=== Domain WHOIS Lookup Tool ===")
    
    raw_input_data = input("Please paste the domains (separated by commas) and press enter:\n> ")
    domains = [d.strip() for d in raw_input_data.split(",") if d.strip()]

    if not domains:
        print(Fore.YELLOW + "[-] No valid domains provided. Exiting.")
        sys.exit(1)

    total_domains = len(domains)
    print(f"\n[*] Loaded {total_domains} domain(s). Starting WHOIS lookups...\n")

    results = []

    for count, domain in enumerate(domains, start=1):
        status, message = perform_whois(domain)
        results.append((domain, status, message))
        update_progress(count, total_domains, f"Querying: {domain[:15]}...")
        
        # Small polite delay between queries to avoid rate limits from WHOIS registries
        if count < total_domains:
            time.sleep(0.4)

    # Print requested block layout format
    print("\n\n" + "=" * 50)
    print("WHOIS Lookup Info")
    print("=================")

    for domain, status, details in results:
        print(f"\nDomain: {domain}")
        print("-" * len(f"Domain: {domain}"))
        
        if status == "SUCCESS":
            print(Fore.GREEN + details)
        else:
            print(Fore.YELLOW + details)
        print()


if __name__ == "__main__":
    main()
