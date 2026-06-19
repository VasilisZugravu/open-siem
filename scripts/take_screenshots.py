"""Capture dashboard screenshots into docs/img/."""
import json
import time
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE = "http://localhost:5000"
OUT = Path(__file__).parent.parent / "docs" / "img"
OUT.mkdir(parents=True, exist_ok=True)


def get_first_alert_id(page):
    page.goto(f"{BASE}/api/alerts", wait_until="networkidle")
    alerts = json.loads(page.inner_text("body"))
    if not alerts:
        raise RuntimeError("No alerts found — run seed_demo_data.py and wait for the scheduler")
    return alerts[0]["id"]


def login(page, username="admin", password="demo"):
    page.goto(f"{BASE}/login", wait_until="networkidle")
    page.fill('input[name="username"]', username)
    page.fill('input[name="password"]', password)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/", timeout=5000)


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})

        login(page)
        alert_id = get_first_alert_id(page)

        routes = [
            ("dashboard",           "/"),
            ("alert-feed",          "/"),
            ("heatmap",             "/heatmap"),
            ("event-explorer",      "/events"),
            ("alert-detail",        f"/alerts/{alert_id}"),
            ("attack-simulator",    "/attack"),
        ]

        for name, path in routes:
            page.goto(f"{BASE}{path}", wait_until="networkidle")
            time.sleep(0.8)  # let Chart.js render
            dest = OUT / f"{name}.png"
            page.screenshot(path=str(dest), full_page=True)
            print(f"saved {dest}")

        browser.close()


if __name__ == "__main__":
    main()
