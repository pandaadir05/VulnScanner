import argparse
import requests
from bs4 import BeautifulSoup
from scanner.scanner import scan_url

def login_dvwa(session, base_url):
    """
    Logs into DVWA by:
      1) GET login.php to fetch CSRF token (user_token)
      2) POST login data with username, password, user_token
    """
    login_url = f"{base_url}/login.php"
    try:
        # 1) Fetch login page to get user_token
        r = session.get(login_url)
        r.raise_for_status()

        soup = BeautifulSoup(r.text, 'html.parser')
        token_field = soup.find('input', {'name': 'user_token'})
        if not token_field or not token_field.get('value'):
            print("[!] Could not find user_token in login form. Check DVWA version or form structure.")
            return False

        user_token = token_field['value']

        # 2) Submit login with the token
        login_payload = {
            'username': 'admin',
            'password': 'password',
            'Login': 'Login',
            'user_token': user_token
        }
        r = session.post(login_url, data=login_payload)
        r.raise_for_status()

        # Check if login was successful
        if "Welcome to Damn Vulnerable Web App!" in r.text or "You have logged in as" in r.text:
            print("[*] Successfully logged into DVWA!")
            return True
        else:
            print("[!] Login response didn't contain expected text. Possibly wrong creds or DVWA not set up.")
            return False

    except requests.exceptions.RequestException as e:
        print(f"[!] Error during login attempt: {e}")
        return False

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
    args = parser.parse_args()

    # Create a shared requests session (to maintain cookies if we login)
    session = requests.Session()

    # If --login is provided, attempt DVWA login
    if args.login:
        success = login_dvwa(session, args.base)
        if not success:
            print("[!] DVWA login failed; scanning might be limited to public pages.")

    print(f"[*] Starting scan for {args.url}")
    # pass crawl option to scan_url if we want recursion
    scan_url(args.url, session=session, do_crawl=args.crawl)
    print("[*] Scan complete.")

    # Generate HTML report if --report is provided
    if args.report:
        from scanner.scanner import write_html_report
        write_html_report(args.report)
        print(f"[*] Report saved to {args.report}")

if __name__ == "__main__":
    main()
