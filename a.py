import requests
import urllib.parse
import sys
import re
from colorama import Fore, Style, init

init(autoreset=True)

def load_payloads(filename):
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"[!] Payload file '{filename}' not found.")
        sys.exit(1)

def is_payload_reflected(response_text, payload):
    return payload in response_text

def scan_xss(target_url, payloads):
    parsed = urllib.parse.urlparse(target_url)
    query_params = urllib.parse.parse_qs(parsed.query)

    if not query_params:
        print(Fore.YELLOW + "[!] No query parameters found to test.")
        return

    print(Fore.CYAN + f"[*] Scanning {target_url} for XSS...\n")

    for param in query_params:
        for payload in payloads:
            # Clone parameters and inject payload
            test_params = query_params.copy()
            test_params[param] = payload
            new_query = urllib.parse.urlencode(test_params, doseq=True)

            # Construct new URL
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (XSS Scanner)",
                    "Accept": "*/*"
                }
                response = requests.get(test_url, headers=headers, timeout=5, verify=False)

                if is_payload_reflected(response.text, payload):
                    print(Fore.RED + f"[!] XSS Detected!")
                    print(Fore.RED + f"    URL: {test_url}")
                    print(Fore.RED + f"    Parameter: {param}")
                    print(Fore.RED + f"    Payload: {payload}\n")
            except requests.exceptions.RequestException as e:
                print(Fore.YELLOW + f"[!] Request failed for {test_url} - {e}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python xss_scanner.py <target_url> <payload_file>")
        print("Example: python xss_scanner.py \"http://example.com/search?q=test\" xss.txt")
        sys.exit(1)

    target_url = sys.argv[1]
    payload_file = sys.argv[2]
    payloads = load_payloads(payload_file)

    scan_xss(target_url, payloads)

if __name__ == "__main__":
    main()
