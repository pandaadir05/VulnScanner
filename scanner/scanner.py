from urllib.parse import urlparse, parse_qs
from scanner.crawler import fetch_html, get_links, get_forms
from scanner.vulns import (
    check_sqli,
    check_xss,
    check_cmd_injection,
)

# Global list to store results
results = []

def record_result(vuln_type, url, payload):
    results.append({
        "type": vuln_type,
        "url": url,
        "payload": payload
    })

def scan_url(start_url, session=None, do_crawl=False, visited=None):
    """
    Fetch the page, test query params, test forms, optionally crawl links.
    :param start_url: the initial URL to scan
    :param session: requests.Session() object
    :param do_crawl: if True, recursively crawl links on the same domain
    :param visited: a set of visited URLs to avoid infinite loops
    """
    if visited is None:
        visited = set()

    if start_url in visited:
        return  # already scanned
    visited.add(start_url)

    html_content = fetch_html(start_url, session=session)
    if not html_content:
        print(f"[!] No HTML content at {start_url}. Skipping.")
        return

    # 1. Check for query parameters in the start URL
    parsed = urlparse(start_url)
    query_params = parse_qs(parsed.query)  # returns {param: [value,...]}
    if query_params:
        # Flatten the dictionary to {param: first_value}
        flat_params = {k: v[0] for k, v in query_params.items()}
        sqli_found = check_sqli(start_url, flat_params, method='get', session=session)
        xss_found = check_xss(start_url, flat_params, method='get', session=session)
        cmd_found = check_cmd_injection(start_url, flat_params, method='get', session=session)

        if not any([sqli_found, xss_found, cmd_found]):
            print(f"[*] No vulnerabilities found in query params at {start_url}.")
    else:
        print(f"[*] No query params to test at {start_url}.")

    # 2. Check forms on this page
    forms = get_forms(html_content, start_url)
    if forms:
        for form in forms:
            action = form['action']
            method = form['method']
            inputs = form['inputs']

            # Build dict with dummy 'test' values
            params_dict = {}
            for (inp_name, inp_type) in inputs:
                if inp_name:
                    params_dict[inp_name] = "test"

            sqli_found = check_sqli(action, params_dict, method=method, session=session)
            xss_found = check_xss(action, params_dict, method=method, session=session)
            cmd_found = check_cmd_injection(action, params_dict, method=method, session=session)

            if not any([sqli_found, xss_found, cmd_found]):
                print(f"[*] Form at {action} not vulnerable (with basic checks).")
    else:
        print(f"[*] No forms found on {start_url}.")

    # 3. (Optional) Crawl more links within the same domain
    if do_crawl:
        domain = f"{parsed.scheme}://{parsed.netloc}"
        links = get_links(html_content, start_url)
        for link in links:
            # only crawl if same domain
            if link.startswith(domain):
                scan_url(link, session=session, do_crawl=True, visited=visited)

def write_html_report(filename="report.html"):
    with open(filename, "w", encoding="utf-8") as f:
        f.write("<html><head><title>Scan Report</title></head><body>")
        f.write("<h1>Web Scanner Report</h1>")
        if not results:
            f.write("<p>No vulnerabilities found.</p>")
        else:
            f.write("<ul>")
            for r in results:
                f.write(f"<li>{r['type']} at {r['url']} with payload '{r['payload']}'</li>")
            f.write("</ul>")
        f.write("</body></html>")

# At the end of scan_url, or in main.py after we call scan_url, do:
# write_html_report()
