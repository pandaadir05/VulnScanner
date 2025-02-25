# main.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from scanner.scanner import scan_url

def login_dvwa_session(base_url="http://localhost:8080"):
    """
    Logs into DVWA (admin/password) and returns a requests.Session with cookies set.
    After posting to login.php, it explicitly requests the index page to confirm login.
    """
    # Remove any trailing slash from the base URL to prevent double slashes later.
    base_url = base_url.rstrip("/")
    session = requests.Session()

    try:
        # 1. Fetch login page to get CSRF token
        login_page = session.get(f"{base_url}/login.php")
        soup = BeautifulSoup(login_page.text, "html.parser")
        token_field = soup.find("input", {"name": "user_token"})
        if not token_field:
            print("[!] Could not find user_token in DVWA login form.")
            return session

        user_token = token_field.get("value", "")
        # 2. Submit login with credentials and CSRF token
        payload = {
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": user_token
        }
        session.post(f"{base_url}/login.php", data=payload)
        # 3. Explicitly request the index page to confirm login
        index_page = session.get(f"{base_url}/index.php")
        if "Welcome" in index_page.text and "Damn Vulnerable Web Application" in index_page.text:
            print("[*] Successfully logged in to DVWA!")
        else:
            print("[!] DVWA login may have failed. Check credentials or DVWA setup.")

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to connect to {base_url}: {e}")

    return session

def get_vulnerability_pages(session, base_url):
    """
    Extracts all vulnerability page URLs from DVWA's vulnerabilities page.
    """
    # Clean up base_url
    base_url = base_url.rstrip("/")
    vuln_urls = []
    
    try:
        vuln_page = session.get(f"{base_url}/vulnerabilities/")
        if vuln_page.status_code != 200:
            print(f"[!] Failed to access vulnerabilities page. Status Code: {vuln_page.status_code}")
            return vuln_urls

        soup = BeautifulSoup(vuln_page.text, "html.parser")
        links = soup.find_all("a", href=True)
        print(f"[*] Found {len(links)} links on vulnerabilities page.")

        for link in links:
            href = link["href"]
            # Accept both absolute and relative links that mention 'vulnerabilities'
            if href.startswith("/vulnerabilities/") or href.startswith("vulnerabilities/"):
                full_url = urljoin(base_url, href)
                vuln_urls.append(full_url)
                print(f"[DEBUG] Found vulnerability page: {full_url}")

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch vulnerability pages: {e}")

    # Fallback in case no vulnerability pages were auto-discovered
    if not vuln_urls:
        print("[!] No vulnerability pages found. Using fallback list.")
        fallback = [
            "vulnerabilities/sqli/",
            "vulnerabilities/csrf/",
            "vulnerabilities/xss_d/",
            "vulnerabilities/xss_r/",
            "vulnerabilities/exec/"
        ]
        for path in fallback:
            full_url = f"{base_url}/{path}"
            vuln_urls.append(full_url)
            print(f"[DEBUG] Fallback URL: {full_url}")

    return vuln_urls

def main():
    base_url = "http://localhost:8080"  # Adjust if needed
    # Log in and get the session
    session = login_dvwa_session(base_url)
    # Get the vulnerability pages from DVWA
    vuln_pages = get_vulnerability_pages(session, base_url)
    # Scan each vulnerability page
    for page in vuln_pages:
        print(f"[*] Scanning {page}")
        scan_url(page, session=session, checks=["sqli", "xss", "cmdi", "stored_xss"], do_crawl=True)
    print("[*] Scan complete.")
    print("[*] Report saved to report.html")

if __name__ == "__main__":
    main()
