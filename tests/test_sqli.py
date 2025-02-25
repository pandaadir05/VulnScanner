import pytest
from scanner.vulns import check_sqli

def test_check_sqli_no_params():
    # If no params exist, we expect no vulnerabilities found
    vulnerable = check_sqli(url="http://example.com", params={})
    assert vulnerable == False

def test_check_sqli_mock_response(monkeypatch):
    class MockResponse:
        text = "SQL syntax error near 'OR 1=1'"

    def mock_get(url, params=None):
        return MockResponse()

    # monkeypatch session.get
    monkeypatch.setattr("requests.get", mock_get)

    # Now call check_sqli
    vulnerable = check_sqli(url="http://example.com", params={"id": "1"})
    assert vulnerable == True
