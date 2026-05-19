import re
from urllib.parse import urlparse
from datetime import datetime
import whois

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "verify", "account", "update",
    "bank", "paypal", "signin", "confirm", "password"
]

SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf"]

POPULAR_BRANDS = [
    "paypal", "google", "facebook", "amazon",
    "apple", "microsoft", "netflix", "instagram"
]

def get_domain_age(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            return (datetime.now() - creation_date).days
        return -1
    except:
        return -1


def check_brand_spoof(domain):
    for brand in POPULAR_BRANDS:
        if brand in domain:
            return brand
    return None


# 🔥 FINAL FIXED FUNCTION
def extract_features_with_reason(url, use_whois=True):
    features = []
    reasons = []
    score = 0

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # 1 URL length
    length = len(url)
    features.append(length)
    if length > 50:
        reasons.append("Long URL")
        score += 10

    # 2 @
    has_at = 1 if '@' in url else 0
    features.append(has_at)
    if has_at:
        reasons.append("Contains @")
        score += 20

    # 3 HTTPS
    has_https = 1 if url.startswith("https") else 0
    features.append(has_https)
    if not has_https:
        reasons.append("No HTTPS")
        score += 15

    # 4 dots
    dots = url.count('.')
    features.append(dots)
    if dots > 3:
        reasons.append("Too many dots")
        score += 10

    # 5 IP
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    has_ip = 1 if re.search(ip_pattern, url) else 0
    features.append(has_ip)
    if has_ip:
        reasons.append("IP used")
        score += 20

    # 6 hyphen
    has_hyphen = 1 if '-' in domain else 0
    features.append(has_hyphen)
    if has_hyphen:
        reasons.append("Hyphen in domain")
        score += 5

    # 7 keywords
    keyword_flag = 0
    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            keyword_flag = 1
            reasons.append(f"Suspicious keyword: {word}")
            score += 5
    features.append(keyword_flag)

    # 8 TLD
    tld_flag = 0
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            tld_flag = 1
            reasons.append("Suspicious domain extension")
            score += 10
    features.append(tld_flag)

    # 9 brand spoof
    brand = check_brand_spoof(domain)
    brand_flag = 1 if brand else 0
    features.append(brand_flag)
    if brand:
        reasons.append(f"Brand spoofing: {brand}")
        score += 20

    # 10 domain age
    if use_whois:
        age = get_domain_age(url)
    else:
        age = -1

    age_flag = 0
    if age == -1:
        reasons.append("Domain age unknown")
        score += 10
        age_flag = 1
    elif age < 180:
        reasons.append("New domain")
        score += 15
        age_flag = 1

    features.append(age_flag)

    score = min(score, 100)

    return features, score, reasons