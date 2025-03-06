import requests
from config import HEADERS, REQUEST_TIMEOUT, ENABLE_XSS_CHECK, ENABLE_SQLI_CHECK

XSS_TEST_SCRIPT = "<script>alert('XSS')</script>"
SQL_TEST_PAYLOADS = ["'", '"', " OR 1=1 --", " OR '1'='1"]

def check_xss(url, method, form):
    """Checks for XSS vulnerability."""
    inputs = form.find_all("input")
    data = {inp.get("name", ""): XSS_TEST_SCRIPT for inp in inputs}
    
    if method == "post":
        response = requests.post(url, data=data)
    else:
        response = requests.get(url, params=data)
    
    return XSS_TEST_SCRIPT in response.text

def check_sql_injection(url, method, form):
    """Checks for SQL Injection vulnerability."""
    inputs = form.find_all("input")
    for payload in SQL_TEST_PAYLOADS:
        data = {inp.get("name", ""): payload for inp in inputs}
        
        if method == "post":
            response = requests.post(url, data=data)
        else:
            response = requests.get(url, params=data)
        
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            return True
    return False