from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re

def analyze_security(soup, base_url):
    report = {}
    risk_score = 0

    base_domain = urlparse(base_url).netloc
    page_text = soup.prettify()

    scripts = soup.find_all("script")

    # -----------------------------
    # Suspicious JS Patterns
    # -----------------------------
    suspicious_patterns = [
        r"eval\(",
        r"document\.write\(",
        r"atob\(",
        r"btoa\(",
        r"setTimeout\(",
        r"setInterval\(",
        r"Function\(",
        r"window\.location",
    ]

    pattern_hits = []

    for pattern in suspicious_patterns:
        if re.search(pattern, page_text):
            pattern_hits.append(pattern)

    if pattern_hits:
        report["suspicious_patterns"] = pattern_hits
        risk_score += 3

    # -----------------------------
    # Inline Scripts
    # -----------------------------
    inline_scripts = [s for s in scripts if not s.get("src")]

    if inline_scripts:
        report["inline_scripts"] = len(inline_scripts)
        risk_score += 2

    # Long Inline Scripts (Possible Obfuscation)
    long_scripts = [
        s for s in inline_scripts
        if s.string and len(s.string) > 1000
    ]

    if long_scripts:
        report["long_inline_scripts"] = len(long_scripts)
        risk_score += 2

    # -----------------------------
    # External Scripts
    # -----------------------------
    external_scripts = [s.get("src") for s in scripts if s.get("src")]
    suspicious_scripts = []

    for script in external_scripts:
        if script and base_domain not in script:
            suspicious_scripts.append(script)

    if suspicious_scripts:
        report["external_scripts_from_other_domains"] = suspicious_scripts
        risk_score += 2

    # -----------------------------
    # Hidden Iframes
    # -----------------------------
    iframes = soup.find_all("iframe")
    hidden_iframes = [
        i for i in iframes
        if i.has_attr("style") and "display:none" in i["style"]
    ]

    if hidden_iframes:
        report["hidden_iframes"] = len(hidden_iframes)
        risk_score += 3

    # -----------------------------
    # Suspicious Form Actions
    # -----------------------------
    forms = soup.find_all("form")
    external_forms = []

    for form in forms:
        action = form.get("action")
        if action and base_domain not in action:
            external_forms.append(action)

    if external_forms:
        report["external_form_actions"] = external_forms
        risk_score += 2

    # -----------------------------
    # Inline Event Handlers
    # -----------------------------
    event_handlers = []

    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if attr.startswith("on"):
                event_handlers.append(attr)

    if event_handlers:
        report["inline_event_handlers"] = list(set(event_handlers))
        risk_score += 2

    # -----------------------------
    # Risk Level Calculation
    # -----------------------------
    report["risk_score"] = risk_score

    if risk_score <= 2:
        report["risk_level"] = "Low"
    elif risk_score <= 6:
        report["risk_level"] = "Medium"
    else:
        report["risk_level"] = "High"

    return report