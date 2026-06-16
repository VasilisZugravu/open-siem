"""Capture 4 dashboard screenshots into docs/img/."""
import os
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE = "http://localhost:5000"
OUT = Path(__file__).parent.parent / "docs" / "img"
OUT.mkdir(parents=True, exist_ok=True)

PAGES = [
    ("alert-feed",      "/"),
    ("heatmap",         "/heatmap"),
    ("event-explorer",  "/events"),
    ("alert-detail",    None),   # resolved dynamically
]


def get_first_alert_id():
    import urllib.request, json
    with urllib.request.urlopen(f"{BASE}/api/alerts") as r:
        alerts = json.load(r)
    if not alerts:
        raise RuntimeError("No alerts found — run seed_demo_data.py and wait for the scheduler")
    return alerts[0]["id"]


def main():
    alert_id = get_first_alert_id()
    routes = [
        ("alert-feed",     "/"),
        ("heatmap",        "/heatmap"),
        ("event-explorer", "/events"),
        ("alert-detail",   f"/alerts/{alert_id}"),
    ]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})

        for name, path in routes:
            page.goto(f"{BASE}{path}", wait_until="networkidle")
            time.sleep(0.5)  # let Chart.js render
            dest = OUT / f"{name}.png"
            page.screenshot(path=str(dest), full_page=True)
            print(f"saved {dest}")

        browser.close()


if __name__ == "__main__":
    main()
