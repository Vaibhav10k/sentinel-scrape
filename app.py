from flask import Flask, request, jsonify
import requests
from bs4 import BeautifulSoup
from analyzer import analyze_security
import urllib3
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
@app.route("/")
def home():
    return jsonify({"message": "SentinelScrape API is running"})

@app.route("/analyze", methods=["GET"])
def analyze():
    url = request.args.get("url")

    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    try:
        response = requests.get(url, timeout=5, verify=False)
        response.raise_for_status()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    soup = BeautifulSoup(response.text, 'html.parser')

    data = {
        "title": soup.title.string if soup.title else "No Title",
        "headings": [h.text.strip() for h in soup.find_all(['h1','h2','h3'])],
        "links": [a['href'] for a in soup.find_all('a', href=True)],
        "forms": len(soup.find_all('form')),
        "security_analysis": analyze_security(soup, url)
    }

    return jsonify(data)

if __name__ == "__main__":
    app.run(debug=True)