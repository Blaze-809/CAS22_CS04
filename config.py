HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

REQUEST_TIMEOUT = 5

SQL_TEST_PAYLOADS = ["'", '"', " OR 1=1 --", " OR '1'='1", "' OR 'a'='a"]

XSS_TEST_SCRIPT = "<script>alert('XSS')</script>"

OPEN_REDIRECT_TEST_URL = "http://evil.com"  

ENABLE_XSS_CHECK = True
ENABLE_SQLI_CHECK = True
ENABLE_OPEN_REDIRECT_CHECK = True