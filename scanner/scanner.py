# scanner/scanner.py

from urllib.parse import urlparse, parse_qs
from scanner.crawler import fetch_html, get_links, get_forms
from scanner.vulns import check_sqli, check_xss

def scan_url(start_url):
    """Crawl the URL, find parameters, and test for vulnerabilities."""
    html_content = fetch_html(start_url)
    if not html_content:
        return

    # 1. Check if there are query params in the start URL
    parsed = urlparse(start_url)
    query_params = parse_qs(parsed.query)  # returns {param: [value], ...}
    if query_params:
        # flatten into dict: {param: value}
        flat_params = {k: v[0] for k, v in query_params.items()}
        check_sqli(start_url, flat_params, method='get')
        check_xss(start_url, flat_params, method='get')

    # 2. Check forms on this page
    forms = get_forms(html_content, start_url)
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']

        # Build params dict
        params_dict = {}
        for (inp_name, inp_type) in inputs:
            if inp_name:  # use a dummy value, can be refined later
                params_dict[inp_name] = "test"

        check_sqli(action, params_dict, method=method)
        check_xss(action, params_dict, method=method)

    # 3. Optional: Crawl further links (if you want recursion)
    #    Just be mindful of infinite loops or domain restrictions.
    # links = get_links(html_content, start_url)
    # for link in links:
    #     if same domain, not visited: scan_url(link)
