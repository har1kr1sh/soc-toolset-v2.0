import sys
import subprocess
import time
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)


def print_banner():
    """Displays a vibrant, top-to-bottom RGB gradient ASCII banner for SOC TOOLSET."""
    banner = f"""
{Style.BRIGHT}{Fore.LIGHTRED_EX} ███████╗ ██████╗  ██████╗     ████████╗ ██████╗  ██████╗ ██╗      ███████╗███████╗████████╗
{Style.BRIGHT}{Fore.LIGHTYELLOW_EX} ██╔════╝██╔═══██╗██╔════╝     ╚══██╔══╝██╔═══██╗██╔═══██╗██║      ██╔════╝██╔════╝╚══██╔══╝
{Style.BRIGHT}{Fore.LIGHTGREEN_EX} ███████╗██║   ██║██║             ██║   ██║   ██║██║   ██║██║      ███████╗█████╗     ██║   
{Style.BRIGHT}{Fore.LIGHTCYAN_EX} ╚════██║██║   ██║██║             ██║   ██║   ██║██║   ██║██║      ╚════██║██╔══╝     ██║   
{Style.BRIGHT}{Fore.LIGHTBLUE_EX} ███████║╚██████╔╝╚██████╗        ██║   ╚██████╔╝╚██████╔╝███████╗ ███████║███████╗   ██║   
{Style.BRIGHT}{Fore.LIGHTMAGENTA_EX} ╚══════╝ ╚═════╝  ╚═════╝        ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝ ╚══════╝╚══════╝   ╚═╝   
{Fore.YELLOW}=====================================================================================================
{Fore.GREEN}                   UNIFIED AUTOMATED SECURITY ASSESSMENT TOOLKIT | @har1kr1sh                          
{Fore.YELLOW}=====================================================================================================
{Style.RESET_ALL}"""
    print(banner)


def main():
    while True:
        print_banner()
        print(Fore.GREEN + "[1] File Hash Reputation Checker (VirusTotal)")
        print(Fore.GREEN + "[2] Domain Reputation Scanner (VirusTotal)")
        print(Fore.GREEN + "[3] Domain WHOIS Lookup Tool")
        print(Fore.GREEN + "[4] IP Abuse Reputation Checker (IP Check)")
        print(Fore.GREEN + "[5] VPN / Proxy Detection Inspector")
        print(Fore.GREEN + "[6] Email Data Breach Lookup (XposedOrNot)")
        print(Fore.YELLOW + "[7] Exit Toolkit")
        print(Fore.CYAN + "-" * 101)
        
        choice = input(Fore.WHITE + "Select an option (1-7): ").strip()
        
        # Mapping menu choices to your exact script filenames
        script_map = {
            "1": "vt_hash.py",
            "2": "domain_scan.py",
            "3": "domain_whois.py",
            "4": "ipcheck.py",
            "5": "vpn_detect.py",
            "6": "breach.py"
        }
        
        if choice in script_map:
            script_name = script_map[choice]
            print(Fore.YELLOW + f"\n[*] Launching {script_name}...\n" + "-" * 60)
            try:
                # Run the chosen script using the current python interpreter
                subprocess.run([sys.executable, script_name])
            except Exception as e:
                print(Fore.RED + f"[-] Error running {script_name}: {e}")
            
            input(Fore.CYAN + "\n[+] Task complete. Press Enter to return to the main menu...")
            print("\n" * 2)
            
        elif choice == "7":
            print(Fore.CYAN + "\nExiting Security Toolkit. Stay secure!\n")
            sys.exit(0)
        else:
            print(Fore.RED + "\n[-] Invalid option. Please choose a number between 1 and 7.\n")
            time.sleep(1)


if __name__ == "__main__":
    main()
