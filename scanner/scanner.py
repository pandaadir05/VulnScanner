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
    if checks is None:
        checks = ["sqli", "xss", "cmdi", "stored_xss"]  # default all

    if not PLUGINS:
        init_scanner()

    if session is None:
        session = requests.Session()
    if visited is None:
        visited = set()

    if start_url in visited:
        return  # already scanned
    visited.add(start_url)

    try:
        response = session.get(start_url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch {start_url}: {e}")
        return

    html_content = response.text
    if not html_content:
        print(f"[!] No HTML content at {start_url}. Skipping.")
        return

    # 1. Check query parameters in the URL
    parsed = urlparse(start_url)
    query_params = parse_qs(parsed.query)  # returns {param: [value,...]}
    if query_params:
        flat_params = {k: v[0] for k, v in query_params.items()}
        if "sqli" in checks:
            payload = check_sqli(start_url, flat_params, method='get', session=session)
            if payload:
                record_result("SQL Injection", start_url, payload)
        if "xss" in checks:
            payload = check_xss(start_url, flat_params, method='get', session=session)
            if payload:
                record_result("XSS", start_url, payload)
        if "cmdi" in checks:
            payload = check_cmd_injection(start_url, flat_params, method='get', session=session)
            if payload:
                record_result("Command Injection", start_url, payload)
        if not any([check_sqli(start_url, flat_params, method='get', session=session),
                    check_xss(start_url, flat_params, method='get', session=session),
                    check_cmd_injection(start_url, flat_params, method='get', session=session)]):
            print(f"[*] No vulnerabilities found in query params at {start_url}.")
    else:
        print(f"[*] No query params to test at {start_url}.")

    # 2. Check forms on the page
    forms = get_forms(html_content, start_url)
    if forms:
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.get('inputs', [])
            print("DEBUG: inputs =", inputs)
            # Build a dictionary from form inputs (skip ones with None as key)
            params_dict = {key: value for key, value in inputs if key}
            if "stored_xss" in checks:
                payload = check_stored_xss_submit(action, params_dict, session=session)
                if payload:
                    record_result("Stored XSS", action, payload)
                else:
                    print(f"[*] Form at {action} not vulnerable to stored XSS (basic check).")
            else:
                if "sqli" in checks:
                    payload = check_sqli(action, params_dict, method=method, session=session)
                    if payload:
                        record_result("SQL Injection", action, payload)
                    else:
                        print(f"[*] Form at {action} not vulnerable to SQL Injection (basic check).")
                if "xss" in checks:
                    payload = check_xss(action, params_dict, method=method, session=session)
                    if payload:
                        record_result("XSS", action, payload)
                    else:
                        print(f"[*] Form at {action} not vulnerable to XSS (basic check).")
                if "cmdi" in checks:
                    payload = check_cmd_injection(action, params_dict, method=method, session=session)
                    if payload:
                        record_result("Command Injection", action, payload)
                    else:
                        print(f"[*] Form at {action} not vulnerable to Command Injection (basic check).")
            # Run any plugin check functions
            for plugin in PLUGINS:
                checker = plugin.get("checker")
                if checker:
                    plugin_found = checker(action, params_dict, method, session)
                    if plugin_found:
                        record_result(plugin['name'], action, "Plugin reported vulnerability")
                        print(f"[!] Plugin {plugin['name']} found vulnerability at {action}.")
    else:
        print(f"[*] No forms found on {start_url}.")

    # 3. Optionally crawl links within the same domain
    if do_crawl:
        domain = f"{parsed.scheme}://{parsed.netloc}"
        links = get_links(html_content, start_url)
        for link in links:
            if link.startswith(domain):
                scan_url(link, session=session, checks=checks, do_crawl=True, visited=visited)

if __name__ == "__main__":
    start_url = "http://localhost:8080"
    scan_url(start_url, do_crawl=True)
