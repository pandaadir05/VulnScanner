import requests
from bs4 import BeautifulSoup

def fetch_html(url, session=None):
    if session is None:
        session = requests
    try:
        response = session.get(url, timeout=5)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching {url}: {e}")
        return None

def get_links(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for anchor in soup.find_all('a', href=True):
        full_link = requests.compat.urljoin(base_url, anchor['href'])
        links.add(full_link)
    return links

def get_forms(html, base_url):
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
