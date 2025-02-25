# scanner/crawler.py

import requests
from bs4 import BeautifulSoup

def fetch_html(url):
    """Fetch the HTML content of the given URL."""
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching {url}: {e}")
        return None

def get_links(html, base_url):
    """Parse the HTML to extract links and convert them to absolute URLs."""
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for anchor in soup.find_all('a', href=True):
        full_link = requests.compat.urljoin(base_url, anchor['href'])
        links.add(full_link)
    return links

def get_forms(html, base_url):
    """Extract forms from the HTML, including their action, method, and inputs."""
    soup = BeautifulSoup(html, 'html.parser')
    forms = []
    for form in soup.find_all('form'):
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = []
        for input_tag in form.find_all(['input', 'textarea']):
            input_name = input_tag.get('name')
            input_type = input_tag.get('type', 'text')
            inputs.append((input_name, input_type))
        form_data = {
            'action': requests.compat.urljoin(base_url, action),
            'method': method,
            'inputs': inputs
        }
        forms.append(form_data)
    return forms
