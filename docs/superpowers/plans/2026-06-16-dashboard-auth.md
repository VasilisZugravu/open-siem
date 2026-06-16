# Dashboard Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a login gate to the SIEM dashboard and an `X-Api-Key` guard on `/api/alerts`, with auth controlled entirely by env vars.

**Architecture:** A new `app/auth.py` module owns the Flask-Login `LoginManager`, an in-memory `User` class, and `init_auth()`. Auth is disabled when `DASHBOARD_PASSWORD` is unset (a `request_loader` auto-logs-in the admin so existing tests need zero changes). Login/logout routes live in the existing `dashboard_bp`. The `/api/alerts` JSON endpoint gets the same `X-Api-Key` guard already on `/ingest`.

**Tech Stack:** Flask-Login 0.6.x, Flask sessions (cookie-based), Bootstrap 5 (already in use), pytest.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `requirements.txt` | modify | add flask-login |
| `app/auth.py` | **create** | LoginManager, User class, init_auth() |
| `app/__init__.py` | modify | call init_auth, add SECRET_KEY + DASHBOARD_* config |
| `app/dashboard/routes.py` | modify | @login_required on 5 UI routes, /login, /logout, X-Api-Key on /api/alerts |
| `app/dashboard/templates/login.html` | **create** | login form extending base.html |
| `app/dashboard/templates/base.html` | modify | Logout link (shown when authenticated) |
| `attack-lab/validate.py` | modify | --api-key arg, send X-Api-Key header |
| `docker-compose.yml` | modify | expose DASHBOARD_USER, DASHBOARD_PASSWORD, SECRET_KEY |
| `tests/test_auth.py` | **create** | all auth and /api/alerts key tests |

---

## Task 1: Add flask-login dependency

**Files:**
- Modify: `requirements.txt`

- [ ] **Step 1: Add flask-login to requirements.txt**

Replace the contents of `requirements.txt` with:
```
Flask==3.0.3
Flask-SQLAlchemy==3.1.1
Flask-Login==0.6.3
psycopg2-binary==2.9.9
PyYAML==6.0.1
pytest==8.2.0
requests==2.31.0
```

- [ ] **Step 2: Install the new dependency**

Run: `venv/Scripts/pip install flask-login==0.6.3`

Expected output ends with: `Successfully installed flask-login-0.6.3`

- [ ] **Step 3: Verify import**

Run: `venv/Scripts/python -c "from flask_login import LoginManager; print('ok')"`

Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add requirements.txt
git commit -m "feat: add flask-login dependency"
```

---

## Task 2: Auth module and wiring (auth-disabled path)

**Files:**
- Create: `app/auth.py`
- Modify: `app/__init__.py`
- Create: `tests/test_auth.py`

- [ ] **Step 1: Write the failing test (auth disabled — existing routes unaffected)**

Create `tests/test_auth.py`:

```python
import pytest
from app import create_app


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def authed_app():
    """App with DASHBOARD_PASSWORD set — auth enforced."""
    app = create_app({
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "TESTING": True,
        "DASHBOARD_USER": "admin",
        "DASHBOARD_PASSWORD": "secret",
        "INGEST_API_KEY": "test-secret",
        "SECRET_KEY": "test-secret-key",
    })
    with app.app_context():
        yield app


@pytest.fixture
def authed_client(authed_app):
    return authed_app.test_client()


# ── Auth-disabled (no DASHBOARD_PASSWORD) ───────────────────────────────────

def test_auth_disabled_allows_dashboard(client):
    """When DASHBOARD_PASSWORD is not set, / returns 200 without any login."""
    response = client.get("/")
    assert response.status_code == 200
```

- [ ] **Step 2: Run the test — it fails because flask-login is not wired yet**

Run: `venv/Scripts/pytest tests/test_auth.py::test_auth_disabled_allows_dashboard -v`

Expected: FAIL (ImportError or missing login_manager)

- [ ] **Step 3: Create `app/auth.py`**

```python
from flask import current_app
from flask_login import LoginManager, UserMixin

login_manager = LoginManager()


class User(UserMixin):
    def __init__(self, id):
        self.id = id


_admin = User("admin")


@login_manager.user_loader
def load_user(user_id):
    if user_id == "admin":
        return _admin
    return None


def init_auth(app):
    login_manager.login_view = "dashboard.login"
    login_manager.init_app(app)

    @login_manager.request_loader
    def load_user_from_request(request):
        # When no password is configured, auto-authenticate every request so
        # @login_required routes stay accessible without a session cookie.
        if not current_app.config.get("DASHBOARD_PASSWORD"):
            return _admin
        return None
```

- [ ] **Step 4: Update `app/__init__.py`**

Replace the entire file with:

```python
import os
from flask import Flask
from app.db import db


def create_app(config=None):
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///siem.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["INGEST_API_KEY"] = os.environ.get("INGEST_API_KEY")
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["DASHBOARD_USER"] = os.environ.get("DASHBOARD_USER", "admin")
    app.config["DASHBOARD_PASSWORD"] = os.environ.get("DASHBOARD_PASSWORD")

    if config:
        app.config.update(config)

    db.init_app(app)

    from app import models  # noqa: F401 - registers tables with SQLAlchemy
    from app.ingest import ingest_bp
    from app.dashboard.routes import dashboard_bp
    from app.auth import init_auth

    app.register_blueprint(ingest_bp)
    app.register_blueprint(dashboard_bp)
    init_auth(app)

    with app.app_context():
        db.create_all()

    if not app.config.get("TESTING"):
        from app.scheduler import start_background_loop
        start_background_loop(app)

    return app
```

- [ ] **Step 5: Run the test — it should pass now**

Run: `venv/Scripts/pytest tests/test_auth.py::test_auth_disabled_allows_dashboard -v`

Expected: PASS

- [ ] **Step 6: Run the full suite to confirm no regressions**

Run: `venv/Scripts/pytest -v`

Expected: all 66 previously-passing tests still pass (plus 1 new).

- [ ] **Step 7: Commit**

```bash
git add app/auth.py app/__init__.py tests/test_auth.py
git commit -m "feat: add auth module with LoginManager and auth-disabled path"
```

---

## Task 3: Protect dashboard routes with @login_required

**Files:**
- Modify: `app/dashboard/routes.py`
- Modify: `tests/test_auth.py`

- [ ] **Step 1: Write the failing test (unauthenticated redirect)**

Add to `tests/test_auth.py`, after the auth-disabled test:

```python
# ── Auth-enabled (DASHBOARD_PASSWORD set) ───────────────────────────────────

def test_unauthenticated_get_redirects_to_login(authed_client):
    response = authed_client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_unauthenticated_heatmap_redirects_to_login(authed_client):
    response = authed_client.get("/heatmap")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_unauthenticated_events_redirects_to_login(authed_client):
    response = authed_client.get("/events")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
```

- [ ] **Step 2: Run the tests — they fail (routes currently return 200)**

Run: `venv/Scripts/pytest tests/test_auth.py -k "redirects_to_login" -v`

Expected: FAIL (got 200, expected 302)

- [ ] **Step 3: Add @login_required to the five UI routes in `app/dashboard/routes.py`**

Add these imports at the top of the file (after the existing imports):

```python
from flask_login import login_required, login_user, logout_user
```

Then add `@login_required` to each of the five UI routes. The full updated route definitions (just the decorators + signatures — do not change the bodies):

```python
@dashboard_bp.route("/")
@login_required
def alert_feed():
    ...

@dashboard_bp.route("/alerts/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    ...

@dashboard_bp.route("/alerts/<int:alert_id>/status", methods=["POST"])
@login_required
def update_alert_status(alert_id):
    ...

@dashboard_bp.route("/heatmap")
@login_required
def heatmap():
    ...

@dashboard_bp.route("/events")
@login_required
def event_explorer():
    ...
```

Do **not** add `@login_required` to `api_alerts`.

- [ ] **Step 4: Run the redirect tests — they should pass**

Run: `venv/Scripts/pytest tests/test_auth.py -k "redirects_to_login" -v`

Expected: PASS

- [ ] **Step 5: Run the full suite — confirm existing dashboard tests still pass**

Run: `venv/Scripts/pytest -v`

The `test_dashboard.py` tests use the `client` fixture (no `DASHBOARD_PASSWORD`), so they still get auto-authenticated via `request_loader`. All tests should pass.

- [ ] **Step 6: Commit**

```bash
git add app/dashboard/routes.py tests/test_auth.py
git commit -m "feat: protect dashboard routes with login_required"
```

---

## Task 4: Login/logout routes and template

**Files:**
- Modify: `app/dashboard/routes.py`
- Create: `app/dashboard/templates/login.html`
- Modify: `app/dashboard/templates/base.html`
- Modify: `tests/test_auth.py`

- [ ] **Step 1: Write the failing tests (login/logout flow)**

Add to `tests/test_auth.py`:

```python
def test_login_correct_credentials_redirects_to_feed(authed_client):
    response = authed_client.post(
        "/login",
        data={"username": "admin", "password": "secret"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_login_wrong_credentials_rerenders_form(authed_client):
    response = authed_client.post(
        "/login",
        data={"username": "admin", "password": "wrong"},
    )
    assert response.status_code == 200
    assert b"Invalid" in response.data


def test_login_wrong_username_rerenders_form(authed_client):
    response = authed_client.post(
        "/login",
        data={"username": "root", "password": "secret"},
    )
    assert response.status_code == 200
    assert b"Invalid" in response.data


def test_logout_clears_session_and_blocks_dashboard(authed_client):
    authed_client.post("/login", data={"username": "admin", "password": "secret"})
    authed_client.get("/logout", follow_redirects=False)
    response = authed_client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_when_auth_disabled_redirects_to_feed(client):
    """When DASHBOARD_PASSWORD is not set, /login immediately redirects to /."""
    response = client.get("/login", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"] == "/"
```

- [ ] **Step 2: Run the new tests — they fail (login route does not exist yet)**

Run: `venv/Scripts/pytest tests/test_auth.py -k "login or logout" -v`

Expected: FAIL (404 on /login)

- [ ] **Step 3: Add login/logout routes to `app/dashboard/routes.py`**

Add these imports alongside the existing ones at the top:

```python
from flask import flash
from flask_login import login_user, logout_user
```

(You already imported `login_required` in Task 3 — add `flash`, `login_user`, `logout_user` to that same line.)

Add the two new routes **at the end** of `routes.py` (after `api_alerts`):

```python
@dashboard_bp.route("/login", methods=["GET", "POST"])
def login():
    if not current_app.config.get("DASHBOARD_PASSWORD"):
        return redirect(url_for("dashboard.alert_feed"))
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if (username == current_app.config.get("DASHBOARD_USER", "admin")
                and password == current_app.config["DASHBOARD_PASSWORD"]):
            from app.auth import _admin
            login_user(_admin)
            next_page = request.args.get("next") or url_for("dashboard.alert_feed")
            return redirect(next_page)
        flash("Invalid username or password.")
    return render_template("login.html")


@dashboard_bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("dashboard.login"))
```

- [ ] **Step 4: Create `app/dashboard/templates/login.html`**

```html
{% extends "base.html" %}
{% block title %}Sign in — SIEM{% endblock %}
{% block content %}
<div class="row justify-content-center mt-5">
  <div class="col-sm-8 col-md-5 col-lg-4">
    <div class="card shadow-sm">
      <div class="card-body p-4">
        <h5 class="card-title mb-1">Sign in</h5>
        <p class="text-muted small mb-4">SOC Dashboard</p>
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <div class="alert alert-danger py-2 small">{{ messages[0] }}</div>
          {% endif %}
        {% endwith %}
        <form method="post">
          <div class="mb-3">
            <label class="form-label small fw-medium">Username</label>
            <input name="username" type="text" class="form-control" autofocus>
          </div>
          <div class="mb-4">
            <label class="form-label small fw-medium">Password</label>
            <input name="password" type="password" class="form-control">
          </div>
          <button type="submit" class="btn btn-dark w-100">Sign in</button>
        </form>
      </div>
    </div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 5: Add Logout link to `app/dashboard/templates/base.html`**

Replace the `<div>` block inside the navbar (the one with the nav links) with:

```html
<div>
    <a class="nav-link d-inline text-light" href="{{ url_for('dashboard.alert_feed') }}">Alerts</a>
    <a class="nav-link d-inline text-light" href="{{ url_for('dashboard.heatmap') }}">ATT&amp;CK Heatmap</a>
    <a class="nav-link d-inline text-light" href="{{ url_for('dashboard.event_explorer') }}">Events</a>
    {% if current_user.is_authenticated %}
    <a class="nav-link d-inline text-light" href="{{ url_for('dashboard.logout') }}">Logout</a>
    {% endif %}
</div>
```

- [ ] **Step 6: Run the login/logout tests**

Run: `venv/Scripts/pytest tests/test_auth.py -k "login or logout" -v`

Expected: all PASS

- [ ] **Step 7: Run the full suite**

Run: `venv/Scripts/pytest -v`

Expected: all 66 + 9 new = 75 tests pass.

- [ ] **Step 8: Commit**

```bash
git add app/dashboard/routes.py app/dashboard/templates/login.html app/dashboard/templates/base.html tests/test_auth.py
git commit -m "feat: add login/logout routes and login template"
```

---

## Task 5: X-Api-Key guard on /api/alerts

**Files:**
- Modify: `app/dashboard/routes.py`
- Modify: `tests/test_auth.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_auth.py`:

```python
# ── /api/alerts key guard ────────────────────────────────────────────────────

def test_api_alerts_requires_key_when_configured(authed_client):
    response = authed_client.get("/api/alerts")
    assert response.status_code == 401
    assert response.get_json()["error"] == "unauthorized"


def test_api_alerts_with_correct_key_returns_200(authed_client):
    response = authed_client.get("/api/alerts", headers={"X-Api-Key": "test-secret"})
    assert response.status_code == 200
    assert isinstance(response.get_json(), list)


def test_api_alerts_no_key_configured_allows_through(client):
    """When INGEST_API_KEY is not set, /api/alerts is open (existing behaviour)."""
    response = client.get("/api/alerts")
    assert response.status_code == 200
```

- [ ] **Step 2: Run the new tests — they fail**

Run: `venv/Scripts/pytest tests/test_auth.py -k "api_alerts" -v`

Expected: FAIL (`test_api_alerts_requires_key_when_configured` gets 200, not 401)

- [ ] **Step 3: Add the X-Api-Key guard to `api_alerts` in `app/dashboard/routes.py`**

At the very start of the `api_alerts` function body, add the key check (same pattern as `/ingest`):

```python
@dashboard_bp.route("/api/alerts")
def api_alerts():
    expected_key = current_app.config.get("INGEST_API_KEY")
    if expected_key and request.headers.get("X-Api-Key") != expected_key:
        return jsonify({"error": "unauthorized"}), 401

    rule_id = request.args.get("rule_id")
    # ... rest of function unchanged
```

- [ ] **Step 4: Run the /api/alerts tests**

Run: `venv/Scripts/pytest tests/test_auth.py -k "api_alerts" -v`

Expected: all 3 PASS

- [ ] **Step 5: Run the full suite**

Run: `venv/Scripts/pytest -v`

Expected: all 75 + 3 new = 78 tests pass.

- [ ] **Step 6: Commit**

```bash
git add app/dashboard/routes.py tests/test_auth.py
git commit -m "feat: require X-Api-Key on /api/alerts when INGEST_API_KEY is set"
```

---

## Task 6: Update validate.py to send X-Api-Key

**Files:**
- Modify: `attack-lab/validate.py`
- Modify: `tests/test_validate.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_validate.py` (after the existing 4 tests):

```python
def test_poll_alert_sends_api_key_header():
    """When api_key is provided, the request must carry X-Api-Key."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps([{"id": 1}]).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        _poll_alert(
            "http://localhost:5000", "RULE-001", "2026-06-16T09:00:00",
            api_key="my-key", timeout=10,
        )

    req = mock_urlopen.call_args[0][0]
    # urllib stores headers with capitalize() normalisation: "X-api-key"
    assert req.get_header("X-api-key") == "my-key"
```

- [ ] **Step 2: Run the test — it fails**

Run: `venv/Scripts/pytest tests/test_validate.py::test_poll_alert_sends_api_key_header -v`

Expected: FAIL (`_poll_alert` does not accept `api_key` yet)

- [ ] **Step 3: Update `attack-lab/validate.py`**

Replace the file with the following (all changes marked with `# CHANGED`):

```python
#!/usr/bin/env python3
"""Attack lab validation helper — polls /api/alerts after each scenario."""

import argparse
import datetime
import json
import os  # CHANGED: needed for INGEST_API_KEY env var default
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SCENARIOS = [
    {"num": "01", "name": "SSH Brute Force",    "folder": "01-ssh-bruteforce",     "ext": "sh",  "vm": "Linux",   "rule": "RULE-001", "technique": "T1110"},
    {"num": "02", "name": "Sudo Shadow Edit",   "folder": "02-sudo-shadow-edit",   "ext": "sh",  "vm": "Linux",   "rule": "RULE-002", "technique": "T1548.003"},
    {"num": "03", "name": "New Local User",     "folder": "03-useradd",            "ext": "sh",  "vm": "Linux",   "rule": "RULE-003", "technique": "T1136.001"},
    {"num": "04", "name": "Encoded PowerShell", "folder": "04-encoded-powershell", "ext": "ps1", "vm": "Windows", "rule": "RULE-004", "technique": "T1059.001"},
    {"num": "05", "name": "Office Spawns Shell","folder": "05-office-spawns-shell","ext": "ps1", "vm": "Windows", "rule": "RULE-005", "technique": "T1059"},
    {"num": "06", "name": "Scheduled Task",     "folder": "06-scheduled-task",     "ext": "ps1", "vm": "Windows", "rule": "RULE-006", "technique": "T1053.005"},
    {"num": "07", "name": "LSASS Memory Dump",  "folder": "07-procdump-lsass",     "ext": "ps1", "vm": "Windows", "rule": "RULE-007", "technique": "T1003.001"},
    {"num": "08", "name": "C2 Port Connection", "folder": "08-c2-port",            "ext": "ps1", "vm": "Windows", "rule": "RULE-008", "technique": "T1071"},
]

POLL_INTERVAL = 5
TIMEOUT = 60


def _poll_alert(siem_url, rule_id, since_iso, api_key=None, timeout=TIMEOUT):  # CHANGED: api_key param
    """Poll /api/alerts until an alert is found or timeout expires. Returns alert dict or None."""
    params = urllib.parse.urlencode({"rule_id": rule_id, "since": since_iso})
    url = f"{siem_url}/api/alerts?{params}"
    headers = {"X-Api-Key": api_key} if api_key else {}  # CHANGED
    deadline = time.time() + timeout
    while True:
        try:
            req = urllib.request.Request(url, headers=headers)  # CHANGED
            with urllib.request.urlopen(req, timeout=5) as resp:  # CHANGED
                alerts = json.loads(resp.read())
                if alerts:
                    return alerts[0]
        except (urllib.error.URLError, OSError):
            pass
        if time.time() >= deadline:
            return None
        time.sleep(POLL_INTERVAL)


def _write_coverage_md(results, path):
    """Write COVERAGE.md. results: list of (scenario_dict, result_str) for all 8 scenarios."""
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    lines = [
        "# Attack Lab Coverage",
        "",
        f"Last validated: {ts}",
        "",
        "| # | Scenario | VM | ATT&CK | Rule | Result |",
        "|---|----------|-----|--------|------|--------|",
    ]
    for s, result in results:
        lines.append(
            f"| {s['num']} | {s['name']} | {s['vm']} | {s['technique']} | {s['rule']} | {result} |"
        )
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _run_scenario(siem_url, scenario, api_key=None):  # CHANGED: api_key param
    """Prompt user to run script on VM, poll for alert. Returns '✅' or '❌'."""
    script = f"attack-lab/{scenario['folder']}/run.{scenario['ext']}"
    print(f"\n▶  Scenario {scenario['num']} — {scenario['name']} ({scenario['technique']})")
    print(f"   VM: {scenario['vm']}   Script: {script}")
    since_iso = datetime.datetime.utcnow().isoformat()
    input("   Press Enter when the script has been run on the VM...")
    print(f"   Polling {scenario['rule']}...", end="", flush=True)
    alert = _poll_alert(siem_url, scenario["rule"], since_iso, api_key=api_key)  # CHANGED
    if alert:
        print(f" ✅  (alert id={alert['id']})")
        return "✅"
    print(f" ❌  (no alert within {TIMEOUT}s)")
    return "❌"


def main():
    parser = argparse.ArgumentParser(description="Validate attack lab scenarios against the SIEM.")
    parser.add_argument("--siem", default="http://localhost:5000", help="SIEM base URL")
    parser.add_argument("--scenario", metavar="NUM", help="Run only this scenario number, e.g. 01")
    parser.add_argument(  # CHANGED
        "--api-key",
        default=os.environ.get("INGEST_API_KEY"),
        help="X-Api-Key for /api/alerts (defaults to INGEST_API_KEY env var)",
    )
    args = parser.parse_args()

    to_run = SCENARIOS
    if args.scenario:
        to_run = [s for s in SCENARIOS if s["num"] == args.scenario]
        if not to_run:
            print(f"Unknown scenario: {args.scenario}", file=sys.stderr)
            sys.exit(1)

    results = {s["num"]: (s, "⏳") for s in SCENARIOS}
    for s in to_run:
        results[s["num"]] = (s, _run_scenario(args.siem, s, api_key=args.api_key))  # CHANGED

    coverage_path = "attack-lab/COVERAGE.md"
    _write_coverage_md([results[n] for n in sorted(results)], coverage_path)
    print(f"\nCoverage table written to {coverage_path}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run validate tests**

Run: `venv/Scripts/pytest tests/test_validate.py -v`

Expected: all 5 tests pass (4 existing + 1 new).

- [ ] **Step 5: Run the full suite**

Run: `venv/Scripts/pytest -v`

Expected: all 78 + 1 new = 79 tests pass.

- [ ] **Step 6: Commit**

```bash
git add attack-lab/validate.py tests/test_validate.py
git commit -m "feat: send X-Api-Key header in validate.py when --api-key or INGEST_API_KEY set"
```

---

## Task 7: Expose auth env vars in docker-compose.yml

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Update `docker-compose.yml`**

Replace the entire file with:

```yaml
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_USER: siem
      POSTGRES_PASSWORD: siem
      POSTGRES_DB: siem
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  app:
    build: .
    environment:
      DATABASE_URL: postgresql://siem:siem@db:5432/siem
      SECRET_KEY: change-me-in-production
      DASHBOARD_USER: admin
      DASHBOARD_PASSWORD: changeme
      INGEST_API_KEY: changeme
    ports:
      - "5000:5000"
    depends_on:
      - db

volumes:
  pgdata:
```

- [ ] **Step 2: Run the full suite one final time**

Run: `venv/Scripts/pytest -v`

Expected: 79 tests pass, 0 failures.

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "feat: expose dashboard auth and API key env vars in docker-compose"
```
