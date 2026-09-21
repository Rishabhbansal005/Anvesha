import requests
import json
import sys

repos = [
    "nleelaranga-ai/tracemail-ai",
    "SabarishR08/mailforensic-ai",
    "Tiwari-Praveen-Codes/MailForensic-AI",
    "Aditya23011c/SIH26106-ml-engine",
    "Anand3525M/sih26106-cybernexus",
    "rakeshsinghrawat107/MailTrace-AI",
    "abhinavxsharma/MailTrace-AI-SIH",
    "yeshwanth80/cyberSentials"
]

headers = {'User-Agent': 'Mozilla/5.0'}
data = {}
for r in repos:
    url = f"https://raw.githubusercontent.com/{r}/main/README.md"
    res = requests.get(url, headers=headers)
    if res.status_code != 200:
        url = f"https://raw.githubusercontent.com/{r}/master/README.md"
        res = requests.get(url, headers=headers)
    
    content = res.text if res.status_code == 200 else ""
    data[r] = {
        "status": res.status_code,
        "preview": "\n".join(content.splitlines()[:35])
    }

with open("competitors_summary.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print("Saved competitor summary successfully.")
