# scanner/vulns.py

import requests

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "'; --",
    "' OR 1=1 --"
]

XSS_PAYLOAD = "<script>alert('XSS')</script>"

def check_sqli(url, params, method='get'):
    """Inject known SQLi payloads and look for error strings."""
    error_signatures = ["SQL syntax", "mysql_fetch", "syntax error"]
    for payload in SQLI_PAYLOADS:
        # Create a copy of params with the payload
        test_params = {k: payload for k in params.keys()}
        if method == 'post':
            response = requests.post(url, data=test_params)
        else:
            response = requests.get(url, params=test_params)

        # Check response for known SQL error signatures
        for error_sig in error_signatures:
            if error_sig.lower() in response.text.lower():
                print(f"[!] Possible SQL Injection at {url} with payload {payload}")
                return True
    return False

def check_xss(url, params, method='get'):
    """Inject an XSS payload and see if it appears in the response."""
    test_params = {k: XSS_PAYLOAD for k in params.keys()}
    if method == 'post':
        response = requests.post(url, data=test_params)
    else:
        response = requests.get(url, params=test_params)

    if XSS_PAYLOAD in response.text:
        print(f"[!] Possible XSS at {url} with payload {XSS_PAYLOAD}")
        return True

    return False
