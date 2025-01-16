import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import re

init(autoreset=True)

def resolve_domain(domain):
    try:
        # Strip protocol (http:// or https://) and trailing slashes
        domain = re.sub(r"^https?://", "", domain.strip()).rstrip("/")
        # Resolve domain to IP
        ip = socket.gethostbyname(domain)
        return domain, ip
    except (socket.gaierror, socket.error):
        # Handle invalid domains or resolution errors
        return domain, None

def process_domains(domains, result_file):
    unique_ips = set()  
    total_domains = len(domains)
    resolved_count = 0

    with ThreadPoolExecutor(max_workers=50) as executor:  
        
        future_to_domain = {executor.submit(resolve_domain, domain): domain for domain in domains}

        for future in as_completed(future_to_domain):
            domain, ip = future.result()
            resolved_count += 1

            if ip:
                print(f"[{resolved_count}/{total_domains}] {domain} >> {Fore.GREEN}{ip}{Style.RESET_ALL}")
                unique_ips.add(ip)
                # Update result.txt in real-time
                with open(result_file, "a") as file:
                    file.write(ip + "\n")
            else:
                print(f"[{resolved_count}/{total_domains}] {domain} >> {Fore.RED}Failed to resolve{Style.RESET_ALL}")

    return unique_ips

def main():
  
    input_file = input("Enter the domain list file (e.g., list.txt): ").strip()
    result_file = "result.txt"

    open(result_file, "w").close()

    try:
        with open(input_file, "r") as file:
            domains = file.readlines()
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File '{input_file}' not found!{Style.RESET_ALL}")
        return

    unique_ips = process_domains(domains, result_file)

    print(f"\n{Fore.GREEN}Resolved {len(unique_ips)} unique IPs. Results saved to {result_file}.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
