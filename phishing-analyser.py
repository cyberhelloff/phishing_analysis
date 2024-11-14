#PHISHING ANALYSIS TOOL

import re
import requests
from bs4 import BeautifulSoup

def is_phishing(url):
    # Check if the URL contains common phishing indicators
    phishing_indicators = [
        r'login', r'account', r'secure', r'password', r'verify',
        r'confirm', r'update', r'submit', r'signin', r'signup'
    ]

    for indicator in phishing_indicators:
        if re.search(indicator, url, re.IGNORECASE):
            return True

    # Check if the URL uses HTTPS
    if not url.startswith("https://"):
        return True

    # Check for common phishing patterns (e.g., IP addresses, subdomains)
    ip_pattern = re.compile(r'^https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    if ip_pattern.match(url):
        return True

    subdomain_pattern = re.compile(r'^https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
    if not subdomain_pattern.match(url):
        return True

    # Check for common phishing keywords in the page content
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        if any(indicator in soup.get_text().lower() for indicator in phishing_indicators):
            return True
    except requests.RequestException:
        pass

    return False

def analyze_url(url):
    if is_phishing(url):
        print(f"Warning: The URL {url} is likely a phishing site.")
    else:
        print(f"The URL {url} is likely safe.")

if __name__ == "__main__":
    url = input("Enter the URL to analyze: ")
    analyze_url(url)
