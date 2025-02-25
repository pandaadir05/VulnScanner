# plugins/example_vuln.py

def example_vuln_checker(url, params, method="get", session=None):
    """
    This is a placeholder that tries a trivial test.
    """
    # e.g., do a simple request
    resp = session.get(url)
    if "EXAMPLE_VULN" in resp.text:
        print(f"[!] Found example vuln at {url}")
        return True
    return False

def register():
    return {
        "name": "Example Vuln",
        "description": "A trivial plugin example",
        "checker": example_vuln_checker
    }
