import requests
from bs4 import BeautifulSoup
import json
from analyzer import analyze_security
import argparse

def main():
    parser = argparse.ArgumentParser(description="SentinelScrape - DOM Security Analyzer")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--output", default="report.json", help="Output JSON file")

    args = parser.parse_args()

    try:
        response = requests.get(args.url, timeout=5)
        response.raise_for_status()
    except Exception as e:
        print(f"Error fetching URL: {e}")
        return

    soup = BeautifulSoup(response.text, 'html.parser')

    data = {}
    data['title'] = soup.title.string if soup.title else "No Title"
    data['headings'] = [h.text.strip() for h in soup.find_all(['h1','h2','h3'])]
    data['links'] = [a['href'] for a in soup.find_all('a', href=True)]
    data['forms'] = len(soup.find_all('form'))
    data['security_analysis'] = analyze_security(soup, args.url)

    with open(args.output, "w") as f:
        json.dump(data, f, indent=4)

    print(f"\nReport saved to {args.output}")
    print("Risk Level:", data['security_analysis']['risk_level'])
    print("Risk Score:", data['security_analysis']['risk_score'])

if __name__ == "__main__":
    main()