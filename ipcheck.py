#!/usr/bin/env python3

import sys
import requests
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

# ==========================================
# CONFIGURATION
# ==========================================

API_KEY = "78f582d91413265ea13d0547661649a5741777a3980fa2fb332bff2de9559d80702beea1fea83030"

# ==========================================
# FUNCTIONS
# ==========================================

def update_progress(current, total):
    percent = int((current / total) * 100)
    sys.stdout.write(f"\rChecking IPs.....[{percent}%]")
    sys.stdout.flush()


def check_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=15
        )

        response.raise_for_status()

        data = response.json()["data"]

        reports = data.get("totalReports", 0)
        isp = data.get("isp", "Unknown ISP")

        country = (
            data.get("countryName")
            or data.get("countryCode")
            or "Unknown Country"
        )

        status = "SAFE" if reports == 0 else "UNSAFE"

        message = (
            f"The IP {ip} was observed to be {status} "
            f"and has {reports} report(s) against it. "
            f"It belongs to {isp} and is from {country}."
        )

        return status, message

    except Exception as e:
        return (
            "ERROR",
            f"The IP {ip} could not be checked. Error: {e}"
        )


# ==========================================
# MAIN
# ==========================================

def main():

    print("=" * 70)
    print("ABUSEIPDB BULK IP CHECKER")
    print("=" * 70)

    ip_input = input(
        "\nEnter IP addresses separated by commas:"
    ).strip()

    ips = [ip.strip() for ip in ip_input.split(",") if ip.strip()]

    if not ips:
        print("\nNo IP addresses supplied.")
        return

    results = []

    total_ips = len(ips)

    print("\nStarting analysis...\n")

    for count, ip in enumerate(ips, start=1):
        results.append(check_ip(ip))
        update_progress(count, total_ips)

    print("\n")

    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print()

    safe_count = 0
    unsafe_count = 0
    error_count = 0

    for status, message in results:

        if status == "SAFE":
            safe_count += 1
            print(Fore.GREEN + message)

        elif status == "UNSAFE":
            unsafe_count += 1
            print(Fore.RED + message)

        else:
            error_count += 1
            print(Fore.YELLOW + message)

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    print(Fore.GREEN + f"Safe IPs   : {safe_count}")
    print(Fore.RED + f"Unsafe IPs : {unsafe_count}")

    if error_count:
        print(Fore.YELLOW + f"Errors     : {error_count}")

    print("=" * 70)


if __name__ == "__main__":
    main()
