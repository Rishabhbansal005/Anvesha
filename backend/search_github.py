import requests
import json
import time

headers = {'User-Agent': 'Mozilla/5.0'}
queries = [
    'SIH26106',
    'SIH 26106',
    'AI-Powered Email Threat Detection SIH',
    'Email Threat Detection Geolocation Forensic',
    'email threat detection SIH',
    'email forensic SIH'
]

results = {}
for q in queries:
    url = f'https://api.github.com/search/repositories?q={requests.utils.quote(q)}&sort=updated&order=desc'
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()
        total = data.get('total_count', 0)
        items = data.get('items', [])
        repo_list = []
        for it in items[:6]:
            repo_list.append({
                'name': it.get('full_name'),
                'url': it.get('html_url'),
                'description': it.get('description'),
                'stars': it.get('stargazers_count'),
                'topics': it.get('topics', []),
                'language': it.get('language'),
                'updated_at': it.get('updated_at')
            })
        results[q] = {'total': total, 'repos': repo_list}
    else:
        results[q] = {'error': r.status_code, 'msg': r.text[:200]}
    time.sleep(1)

with open('github_sih_results.json', 'w', encoding='utf-8') as f:
    json.dump(results, f, indent=2)

print("Search completed. Output written to github_sih_results.json")
