#!/usr/bin/env python3
"""Capture documentation screenshots from a running Vigil in DEMO mode (fictional data only).

    docker run -d --name vigil-demo -p 8088:8080 -e VIGIL_DEMO=1 -e VIGIL_AUTH=off vigil:dev    # wait ~3 minutes
    docker run --rm --network host -v "$PWD":/work -w /work mcr.microsoft.com/playwright/python:v1.49.0-noble \
        python scripts/screenshots.py http://localhost:8088 docs/images

Refuses to run unless the instance reports demo mode, so real firewall data never ends up in the docs.
"""
import json
import sys
import urllib.request

from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8088'
OUT = sys.argv[2] if len(sys.argv) > 2 else 'docs/images'
W, H = 1600, 1000

SHOTS = [  # name, hash, wait ms, optional js to run before the shot, full page
    ('home', '#home', 3500, None, False),
    ('live-graph', '#graph', 9000, None, False),
    ('live-graph-capture', '#graph', 9000, "setTimeScale(0); const f = G3.feed.find(x => x.row[3] === 1) || G3.feed[0]; selectRequest(f.row, f.str, f.i)", False),
    ('security-summary', '#security?tab=summary', 4000, None, False),
    ('security-rules', '#security?tab=rules', 4000, None, False),
    ('security-changes', '#security?tab=changes', 3500, None, False),
    ('investigate', '#investigate?q=' + 'ips+blocked', 6000, None, False),
    ('threats', '#utm', 3500, None, False),
    ('activity', '#overview', 3500, None, False),
    ('inbound', '#inbound', 4000, None, False),
    ('outbound', '#outbound', 4000, None, False),
    ('health', '#health', 3000, None, False),
    ('settings', '#settings', 2500, None, False),
    ('welcome', '#welcome', 3000, None, False),
]


def main():
    with urllib.request.urlopen(BASE + '/api/session', timeout=10) as r:
        if not json.load(r).get('demo'):
            raise SystemExit('refusing: this instance is not in demo mode (VIGIL_DEMO=1)')
    with sync_playwright() as p:
        browser = p.chromium.launch(args=['--use-gl=angle', '--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'])
        ctx = browser.new_context(viewport={'width': W, 'height': H}, device_scale_factor=1, color_scheme='dark')
        page = ctx.new_page()
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.on('console', lambda m: m.type == 'error' and errors.append(m.text))
        for name, hsh, wait, js, full in SHOTS:
            page.goto(f'{BASE}/?shot={name}{hsh}')
            page.wait_for_timeout(wait)
            if hsh.startswith('#investigate'):
                first = page.query_selector('#inv-view .tl-row, #inv-view tr.click, #inv-view [data-ref]')
                if first:
                    first.click()
                    page.wait_for_timeout(5000)
            if js:
                page.evaluate(js)
                page.wait_for_timeout(2500)
            page.screenshot(path=f'{OUT}/{name}.png', full_page=full)
            print('saved', name, 'errors so far:', len(errors))
        if len(sys.argv) > 3:                                  # optional: a fresh demo instance with auth on, for the setup page
            page.goto(sys.argv[3] + '/setup')
            page.wait_for_timeout(1500)
            page.screenshot(path=f'{OUT}/setup.png')
            print('saved setup')
        for e in errors:
            print('PAGE ERROR:', e[:300])
        browser.close()


if __name__ == '__main__':
    main()
