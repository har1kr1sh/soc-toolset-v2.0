import sys
import time
import requests
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

BASE_URL = "https://api.xposedornot.com/v1"


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


def check_email(email: str):
    """Query XposedOrNot API for email data breach exposure."""
    email = email.strip()
    if not email:
        return "ERROR", "[-] Empty email provided."

    url = f"{BASE_URL}/check-email/{email}"
    headers = {"accept": "application/json"}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            # XposedOrNot returns breaches as a list of lists/strings under 'breaches'
            breaches_list = data.get("breaches", [])
            
            # Flatten the breaches structure if it's nested
            flattened_breaches = []
            for item in breaches_list:
                if isinstance(item, list):
                    flattened_breaches.extend(item)
                else:
                    flattened_breaches.append(item)

            if flattened_breaches:
                breach_count = len(flattened_breaches)
                breaches_str = ", ".join(flattened_breaches)
                details = (
                    f"Status         : [BREACHED / EXPOSED]\n"
                    f"Breach Count   : {breach_count}\n"
                    f"Breached Sites : {breaches_str}"
                )
                return "UNSAFE", details
            else:
                details = "Status         : [CLEAN / NO BREACHES FOUND]"
                return "SAFE", details

        elif response.status_code == 404:
            details = "Status         : [CLEAN / NO BREACHES FOUND]"
            return "SAFE", details
        else:
            return "ERROR", f"API Error Status {response.status_code}"

    except requests.exceptions.RequestException as e:
        return "ERROR", f"Network Exception: {e}"


def main():
    print(Fore.CYAN + "=== XposedOrNot Free Email Breach Checker ===")
    
    # Prompt user to paste comma-separated email addresses
    raw_input_data = input("Please paste the email addresses (separated by commas) and press enter:\n> ")
    emails = [e.strip() for e in raw_input_data.split(",") if e.strip()]

    if not emails:
        print(Fore.YELLOW + "[-] No valid email addresses provided. Exiting.")
        sys.exit(1)

    total_emails = len(emails)
    print(f"\n[*] Loaded {total_emails} email(s). Starting analysis...\n")

    results = []

    for count, email in enumerate(emails, start=1):
        status, message = check_email(email)
        results.append((email, status, message))
        update_progress(count, total_emails, f"Checking: {email[:15]}...")
        
        # Polite delay to avoid hammering the free public API
        if count < total_emails:
            time.sleep(0.3)

    # Print requested block layout format
    print("\n\n" + "=" * 50)
    print("Breach Detect Info")
    print("==================")

    for email, status, details in results:
        print(f"\nEmail: {email}")
        print("-" * len(f"Email: {email}"))
        
        if status == "SAFE":
            print(Fore.GREEN + details)
        elif status == "UNSAFE":
            print(Fore.RED + details)
        else:
            print(Fore.YELLOW + details)
        print()


if __name__ == "__main__":
    main()
