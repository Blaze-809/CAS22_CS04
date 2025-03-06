import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from utils import check_xss, check_sql_injection, check_open_redirect

def scan_website(url):
    
    print(f"Scanning {url} for vulnerabilities...\n")
    
    forms = get_forms(url)
    print(f"Found {len(forms)} forms on {url}\n")
    
    for form in forms:
        action = form.get("action")
        full_url = urljoin(url, action) if action else url
        method = form.get("method", "get").lower()

        if check_xss(full_url, method, form):
            print(f"[!] XSS vulnerability detected in {full_url}")

        if check_sql_injection(full_url, method, form):
            print(f"[!] SQL Injection vulnerability detected in {full_url}")

    if check_open_redirect(url):
        print(f"[!] Open Redirect vulnerability detected at {url}")

def get_forms(url):
    
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    return soup.find_all("form")

if __name__ == "__main__":
    target_url = input("Enter the website URL to scan: ")
    scan_website(target_url)