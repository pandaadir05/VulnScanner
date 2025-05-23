# **Web Vulnerability Scanner - By Adir Shitrit**  

## **Project Description**  

This is a **Python-powered web vulnerability scanner** built to find security flaws like **SQL Injection, XSS, and Command Injection** in web applications. Designed primarily for **DVWA** but adaptable for other test environments, it **automatically logs in, crawls pages, and tests inputs for vulnerabilities**. Whether you're a security researcher, ethical hacker, or just learning about web security, this tool makes vulnerability scanning simple and effective. Plus, it's **lightweight, extendable, and easy to use!**  

---

## **Features**  

✅ **Automated Login to DVWA** using CSRF token authentication  
✅ **Scans Query Parameters & Forms** for SQL Injection, XSS, and Command Injection  
✅ **Optional Recursive Crawling** to explore deeper vulnerabilities  
✅ **Docker Support** for seamless execution in containerized environments  
✅ **Lightweight & Extendable**—easily add new payloads and security tests  
✅ **Simple & Efficient**—just run and let it do its magic  

---

## **Getting Started**  

### **1️⃣ Clone the Repo & Install Dependencies**  
```bash
git clone https://github.com/Pandaadir05/web-vuln-scanner.git
cd web-vuln-scanner
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

---

## **Docker Usage**  

If you prefer running the scanner inside a **Docker container**, follow these steps:  

### **1️⃣ Build the Docker Image**  
```bash
docker build -t web-vuln-scanner .
```

### **2️⃣ Run the Scanner**  
```bash
docker run --rm web-vuln-scanner --url "http://host.docker.internal:8080/vulnerabilities/sqli/" --login
```
📌 **Note:** This assumes **DVWA is running locally on port 8080**. Modify the URL if your setup is different.

---

## **Basic Usage (Non-Docker)**  

If you're running the scanner **without Docker**, use the following commands:  

```bash
python -m venv venv
source venv/bin/activate
pip install requests beautifulsoup4
python main.py --url "http://localhost:8080/vulnerabilities/sqli/" --login
```
---

## **How to Write a Plugin**

To extend the functionality of VulnScanner, you can create plugins. A plugin is a Python file in the `plugins/` directory that defines a `register()` function. This function should return a dictionary with the following keys:

- `name`: The name of the vulnerability the plugin checks for.
- `description`: A brief description of what the plugin does.
- `checker`: The function that performs the vulnerability check.

### Example Plugin

Here is an example of a simple plugin that checks for a hypothetical vulnerability:

```python
# filepath: plugins/example_plugin.py

def example_checker(url, params, method, session):
    # Your vulnerability checking logic here
    response = session.get(url, params=params)
    if "example_vulnerability" in response.text:
        print(f"[!] Example vulnerability found at {url}")
        return True
    return False

def register():
    return {
        "name": "Example Vulnerability",
        "description": "Checks for an example vulnerability",
        "checker": example_checker
    }
```

### Steps to Create a Plugin

1. **Create a Python file in the `plugins/` directory**:
   - Name the file appropriately, e.g., `example_plugin.py`.

2. **Define the `checker` function**:
   - This function should take the following parameters:
     - `url`: The URL to check.
     - `params`: The parameters to use in the request.
     - `method`: The HTTP method to use (`get` or `post`).
     - `session`: The `requests.Session` object to use for making requests.
   - The function should return `True` if the vulnerability is found, and `False` otherwise.

3. **Define the `register()` function**:
   - This function should return a dictionary with the keys `name`, `description`, and `checker`.

4. **Save the file**:
   - Save the file in the `plugins/` directory.

### Example Usage

Once you have created your plugin, it will be automatically loaded and used by VulnScanner when you run the scan.

```python
# Example usage
if __name__ == "__main__":
    start_url = "http://example.com"
    scan_url(start_url, do_crawl=True)
```

## Docker Compose Setup

1. `docker-compose up -d dvwa` # starts DVWA
2. `docker-compose run scanner --url "http://dvwa/vulnerabilities/sqli/" --login`

---

## **License**  

This project is licensed under the **[MIT License](LICENSE)**.