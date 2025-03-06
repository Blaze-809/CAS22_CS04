import requests
from urllib.parse import urlparse, urlencode
from config import HEADERS

XSS_TEST_SCRIPT = "<script>alert('XSS')</script>"
SQL_TEST_PAYLOADS = ["'", '"', " OR 1=1 --", " OR '1'='1"]
OPEN_REDIRECT_TEST_URL = "http://evil.com"

def check_xss(url, method, form):
    
    inputs = form.find_all("input")
    data = {inp.get("name", ""): XSS_TEST_SCRIPT for inp in inputs}
    
    if method == "post":
        response = requests.post(url, data=data)
    else:
        response = requests.get(url, params=data)
    
    return XSS_TEST_SCRIPT in response.text

def check_sql_injection(url, method, form):
    
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

def check_open_redirect(url):
    
    params = {
        "url": OPEN_REDIRECT_TEST_URL,
        "redirect": OPEN_REDIRECT_TEST_URL
    }
    
    try:
        for param_name in params:
            test_url = f"{url}?{urlencode({param_name: params[param_name]})}"
            response = requests.get(test_url, headers=HEADERS, allow_redirects=True)

            if response.status_code == 200 and urlparse(response.url).netloc == "evil.com":
                return True
    except requests.RequestException:
        pass
    return False