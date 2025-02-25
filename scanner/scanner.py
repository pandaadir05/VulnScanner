import requests
from urllib.parse import urlparse, parse_qs
from scanner.crawler import fetch_html, get_links, get_forms
from scanner.vulns import (
    check_sqli,
    check_xss,
    check_cmd_injection,
    check_stored_xss_submit
)
import os
import importlib

# Global list to store results
results = []

def record_result(vuln_type, url, payload):
    results.append({
        "type": vuln_type,
        "url": url,
        "payload": payload
    })

def load_plugins(plugin_dir="plugins"):
    """
    Dynamically loads all .py files in `plugins/` as modules.
    Expects each to have a `register()` function returning something like:
    {
      "name": "Example Vuln",
      "description": "Checks for some vulnerability",
      "checker": some_function
    }
    """
    plugins = []
    for fname in os.listdir(plugin_dir):
        if fname.endswith(".py") and not fname.startswith("__"):
            module_name = fname[:-3]  # strip .py
            module_path = f"{plugin_dir}.{module_name}"
            mod = importlib.import_module(module_path)
            if hasattr(mod, "register"):
                info = mod.register()
                plugins.append(info)
    return plugins

PLUGINS = []

def init_scanner():
    global PLUGINS
    PLUGINS = load_plugins()  # load all plugin modules once
    print(f"[*] Loaded {len(PLUGINS)} plugins.")

def scan_url(start_url, session=None, checks=None, do_crawl=False, visited=None):
    """
    Fetch the page, test query params, test forms, optionally crawl links.
    :param start_url: the initial URL to scan
    :param session: requests.Session() object
    :param checks: list of checks to perform (e.g., ["sqli", "xss", "cmdi", "stored_xss"])
    :param do_crawl: if True, recursively crawl links on the same domain
    :param visited: a set of visited URLs to avoid infinite loops
    """
    if checks is None:
        checks = ["sqli", "xss", "cmdi", "stored_xss"]  # default all

    # ensure PLUGINS is loaded
    if not PLUGINS:
        init_scanner()

    if session is None:
        session = requests.Session()
    if visited is None:
        visited = set()

    if start_url in visited:
        return  # already scanned
    visited.add(start_url)

    response = session.get(start_url)
    html_content = response.text
    if not html_content:
        print(f"[!] No HTML content at {start_url}. Skipping.")
        return

    # 1. Check for query parameters in the start URL
    parsed = urlparse(start_url)
    query_params = parse_qs(parsed.query)  # returns {param: [value,...]}
    if query_params:
        # Flatten the dictionary to {param: first_value}
        flat_params = {k: v[0] for k, v in query_params.items()}
        if "sqli" in checks:
            sqli_found = check_sqli(start_url, flat_params, method='get', session=session)
        if "xss" in checks:
            xss_found = check_xss(start_url, flat_params, method='get', session=session)
        if "cmdi" in checks:
            cmd_found = check_cmd_injection(start_url, flat_params, method='get', session=session)

        if not any([sqli_found, xss_found, cmd_found]):
            print(f"[*] No vulnerabilities found in query params at {start_url}.")
    else:
        print(f"[*] No query params to test at {start_url}.")

    # 2. Check forms on this page
    forms = get_forms(html_content, start_url)
    if forms:
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.get('inputs', [])
            
            # Debug print statement to check the structure of inputs
            print("DEBUG: inputs =", inputs)
            
            params_dict = {key: value for key, value in inputs}


            # Suppose the action URL is the same page that stores comments
            # We'll attempt a stored XSS if the form might be for 'comments'
            # or 'message' field, etc.
            if "xss_s" in action and "stored_xss" in checks:  # naive example check
                stored_found = check_stored_xss_submit(action, params_dict, session=session)
                if not stored_found:
                    print(f"[*] Form at {action} not vulnerable to stored XSS (basic check).")
            else:
                # existing checks: sqli, xss, cmd_injection, etc.
                if "sqli" in checks:
                    sqli_found = check_sqli(action, params_dict, method=method, session=session)
                    if not sqli_found:
                        print(f"[*] Form at {action} not vulnerable to SQL Injection (basic check).")

                if "xss" in checks:
                    xss_found = check_xss(action, params_dict, method=method, session=session)
                    if not xss_found:
                        print(f"[*] Form at {action} not vulnerable to XSS (basic check).")

                if "cmdi" in checks:
                    cmd_injection_found = check_cmd_injection(action, params_dict, method=method, session=session)
                    if not cmd_injection_found:
                        print(f"[*] Form at {action} not vulnerable to Command Injection (basic check).")

            # Call plugins to check forms
            for plugin in PLUGINS:
                checker = plugin.get("checker")
                if checker:
                    plugin_found = checker(action, params_dict, method, session)
                    if plugin_found:
                        print(f"[!] Plugin {plugin['name']} found vulnerability at {action}.")

    else:
        print(f"[*] No forms found on {start_url}.")

    # 3. (Optional) Crawl more links within the same domain
    if do_crawl:
        domain = f"{parsed.scheme}://{parsed.netloc}"
        links = get_links(html_content, start_url)
        for link in links:
            # only crawl if same domain
            if link.startswith(domain):
                scan_url(link, session=session, checks=checks, do_crawl=True, visited=visited)

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

# Example usage
if __name__ == "__main__":
    start_url = "http://example.com"
    scan_url(start_url, do_crawl=True)
