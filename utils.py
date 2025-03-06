import requests

SQLI_PAYLOADS = ["'", '"', " OR '1'='1", " OR 1=1 --"]

def check_sql_injection(url, method, form):
    """Checks for SQL Injection vulnerabilities."""
    for payload in SQLI_PAYLOADS:
        data = {}
        for input_tag in form.find_all("input"):
            if input_tag.get("name"):
                data[input_tag["name"]] = payload
        
        if method == "post":
            response = requests.post(url, data=data)
        else:
            response = requests.get(url, params=data)

        if "sql" in response.text.lower() or "database error" in response.text.lower():
            return True  # Vulnerable

    return False  # Not vulnerable

def check_xss(url, method, form):
    """Checks for XSS vulnerabilities."""
    xss_payload = "<script>alert('XSS')</script>"
    data = {}

    for input_tag in form.find_all("input"):
        if input_tag.get("name"):
            data[input_tag["name"]] = xss_payload

    if method == "post":
        response = requests.post(url, data=data)
    else:
        response = requests.get(url, params=data)

    if xss_payload in response.text:
        return True  # Vulnerable

    return False  # Not vulnerable

def check_open_redirect(url):
    """Checks for Open Redirect vulnerabilities."""
    redirect_payload = "http://evil.com"
    test_url = f"{url}?redirect={redirect_payload}"

    try:
        response = requests.get(test_url, allow_redirects=False)
        if response.status_code in [301, 302] and redirect_payload in response.headers.get("Location", ""):
            return True  # Vulnerable
    except requests.exceptions.RequestException:
        return False

    return False