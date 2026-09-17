#!/usr/bin/env python3
"""Daily repository statistics for the maintainers (run by .github/workflows/stats.yml).

Collects stars, forks, watchers, open issues, total Docker image downloads and - when STATS_TOKEN is set (a token
with access to repository traffic) - 14-day views, clones, top referrers and top pages. Prints one JSON line, appends
it to stats/daily.jsonl and, when COMMUNITY_URL and STATS_SECRET are set, posts it to the community Google Sheet.
Only aggregate numbers GitHub publishes to repository owners - nothing about individual people.
"""
import datetime as dt
import json
import os
import re
import sys
import urllib.request

REPO = os.environ.get('GITHUB_REPOSITORY', 'vigiltech01/vigil')
OWNER, NAME = REPO.split('/')


def get(url, token=None, accept='application/vnd.github+json'):
    req = urllib.request.Request(url, headers={'Accept': accept, 'User-Agent': 'vigil-stats'})
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read().decode()
    return json.loads(body) if 'json' in accept else body


def main():
    token = os.environ.get('GITHUB_TOKEN')
    traffic_token = os.environ.get('STATS_TOKEN')
    repo = get(f'https://api.github.com/repos/{REPO}', token)
    today = dt.date.today()
    row = {'date': today.isoformat(), 'stars': repo['stargazers_count'], 'forks': repo['forks_count'],
           'watchers': repo['subscribers_count'], 'open_issues': repo['open_issues_count']}
    try:
        page = get(f'https://github.com/{OWNER}/{NAME}/pkgs/container/{NAME}', accept='text/html')
        m = re.search(r'Total downloads</span>\s*<h3 title="(\d+)"', page)
        row['image_downloads'] = int(m.group(1)) if m else None
    except Exception as e:
        print('image downloads unavailable:', e, file=sys.stderr)
        row['image_downloads'] = None
    if traffic_token:
        base = f'https://api.github.com/repos/{REPO}/traffic'
        views, clones = get(f'{base}/views', traffic_token), get(f'{base}/clones', traffic_token)
        yday = (today - dt.timedelta(days=1)).isoformat()
        row.update(views_14d=views['count'], unique_views_14d=views['uniques'], clones_14d=clones['count'],
                   unique_clones_14d=clones['uniques'],
                   views_yesterday=sum(v['count'] for v in views['views'] if v['timestamp'].startswith(yday)),
                   clones_yesterday=sum(v['count'] for v in clones['clones'] if v['timestamp'].startswith(yday)),
                   top_referrers=', '.join(f"{r['referrer']} ({r['count']})" for r in get(f'{base}/popular/referrers', traffic_token)),
                   top_paths=', '.join(f"{p['path']} ({p['count']})" for p in get(f'{base}/popular/paths', traffic_token)[:5]))
    print(json.dumps(row))
    out = os.environ.get('STATS_FILE')
    if out:
        with open(out, 'a') as f:
            f.write(json.dumps(row) + '\n')
    url, secret = os.environ.get('COMMUNITY_URL'), os.environ.get('STATS_SECRET')
    if url and secret:
        body = json.dumps(dict(row, type='stats', secret=secret)).encode()
        req = urllib.request.Request(url, data=body, headers={'Content-Type': 'text/plain;charset=utf-8'})
        with urllib.request.urlopen(req, timeout=30) as r:
            print('sheet:', r.status, r.read(200).decode(errors='replace'))


if __name__ == '__main__':
    main()
