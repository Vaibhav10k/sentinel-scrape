from bs4 import BeautifulSoup
from urllib.parse import urlparse

def analyze_security(soup, base_url):
    report = {}
    risk_score = 0

    # Script Analysis
    scripts = soup.find_all("script")
    inline_scripts = [s for s in scripts if not s.get("src")]

    if inline_scripts:
        report["inline_scripts"] = len(inline_scripts)
        risk_score += 2

    # External Scripts
    external_scripts = [s.get("src") for s in scripts if s.get("src")]
    suspicious_scripts = []

    base_domain = urlparse(base_url).netloc

    for script in external_scripts:
        if base_domain not in script:
            suspicious_scripts.append(script)

    if suspicious_scripts:
        report["external_scripts_from_other_domains"] = suspicious_scripts
        risk_score += 2

    # Hidden iframes
    iframes = soup.find_all("iframe")
    hidden_iframes = [i for i in iframes if "display:none" in str(i)]

    if hidden_iframes:
        report["hidden_iframes"] = len(hidden_iframes)
        risk_score += 3

    # Suspicious keywords
    suspicious_keywords = ["eval(", "document.write(", "atob(", "btoa("]
    page_text = soup.prettify()

    keyword_hits = [kw for kw in suspicious_keywords if kw in page_text]

    if keyword_hits:
        report["suspicious_keywords"] = keyword_hits
        risk_score += 3

    report["risk_score"] = risk_score

    if risk_score <= 2:
        report["risk_level"] = "Low"
    elif risk_score <= 5:
        report["risk_level"] = "Medium"
    else:
        report["risk_level"] = "High"

    return report