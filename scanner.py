import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from utils import check_xss, check_sql_injection

def scan_website(url):
    """Scans the website and returns a list of detected vulnerabilities with solutions."""
    results = []

    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return ["❌ Unable to reach the website!"]
    except requests.exceptions.RequestException:
        return ["❌ Invalid URL or network issue!"]

    forms = get_forms(url)

    for form in forms:
        action = form.get("action")
        full_url = urljoin(url, action) if action else url
        method = form.get("method", "get").lower()

        xss_result = check_xss(full_url, method, form)
        sql_result = check_sql_injection(full_url, method, form)

        if xss_result:
            results.append(f"❗ XSS vulnerability detected in {full_url}")
            results.append("🔹 Solution: Use input validation, encode output, and implement Content Security Policy (CSP).")

        if sql_result:
            results.append(f"❗ SQL Injection vulnerability detected in {full_url}")
            results.append("🔹 Solution: Use prepared statements (parameterized queries) and input validation to prevent SQL Injection.")

    return results if results else ["✅ No vulnerabilities found!"]

def get_forms(url):
    """Extracts all forms from a webpage."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException:
        return []