import requests
from bs4 import BeautifulSoup
import json

url = input("Enter URL: ")

response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')

data = {}

# Title
data['title'] = soup.title.string if soup.title else "No Title"

# Headings
data['headings'] = [h.text.strip() for h in soup.find_all(['h1','h2','h3'])]

# Links
data['links'] = [a['href'] for a in soup.find_all('a', href=True)]

# Forms
data['forms'] = len(soup.find_all('form'))

with open("report.json", "w") as f:
    json.dump(data, f, indent=4)

print("Report saved!")