import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint

class vscanner :
    def _init_(self, target_url: str, max_depth: int=3):
            pass