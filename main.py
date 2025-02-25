import argparse
import requests
from bs4 import BeautifulSoup
from scanner.scanner import scan_url, write_html_report

def login_dvwa_session(base_url="http://localhost:8080"):
    """
    Logs into DVWA (admin/password) and returns a requests.Session with cookies set.
    """
    session = requests.Session()

    # 1. Fetch login page to get CSRF token
    login_page = session.get(f"{base_url}/login.php")
    soup = BeautifulSoup(login_page.text, "html.parser")
    token_field = soup.find("input", {"name": "user_token"})
    if not token_field:
        print("[!] Could not find user_token in DVWA login form.")
        return session

    user_token = token_field.get("value", "")

    # 2. Submit login
    payload = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": user_token
    }
    r = session.post(f"{base_url}/login.php", data=payload)

    if "Welcome to Damn Vulnerable Web App!" in r.text:
        print("[*] Successfully logged in to DVWA!")
    else:
        print("[!] DVWA login may have failed. Check credentials or DVWA setup.")
    return session

def main():
    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Scanner for DVWA")
    parser.add_argument("--url", required=True,
                        help="Target URL to scan (e.g., http://localhost:8080/vulnerabilities/sqli/)")
    parser.add_argument("--login", action="store_true",
                        help="Attempt to log into DVWA before scanning (default creds: admin/password)")
    parser.add_argument("--base", default="http://localhost:8080",
                        help="Base URL for DVWA login (default: http://localhost:8080)")
    parser.add_argument("--crawl", action="store_true",
                        help="(Experimental) Recursively crawl links found on each page within the same domain.")
    parser.add_argument("--report", help="Output HTML report to file (e.g., report.html)")
    parser.add_argument("--checks", nargs='+', default=["sqli", "xss", "cmdi", "stored_xss"],
                        help="Specify which checks to perform (default: all checks)")

    args = parser.parse_args()

    # If --login is provided, attempt DVWA login
    session = None
    if args.login:
        session = login_dvwa_session(args.base)
        if not session:
            print("[!] DVWA login failed; scanning might be limited.")

    print(f"[*] Starting scan for {args.url}")
    # run the main scanning function
    scan_url(args.url, session=session, checks=args.checks, do_crawl=args.crawl)
    print("[*] Scan complete.")

    # Generate HTML report if requested
    if args.report:
        write_html_report(args.report)
        print(f"[*] Report saved to {args.report}")

if __name__ == "__main__":
    main()
