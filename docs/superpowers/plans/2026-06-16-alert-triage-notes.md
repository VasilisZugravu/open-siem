# Alert Triage Notes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a freetext analyst notes field (with last-updated timestamp) to the alert detail page, saved independently from the status dropdown.

**Architecture:** Two nullable columns (`notes`, `notes_updated_at`) are added to the existing `alerts` table — no new table. A new `POST /alerts/<id>/notes` route handles saves. The alert detail template gets a notes textarea form inserted between the status form and the triggering events table. A SQL migration script handles existing DBs; fresh installs pick up the columns via `db.create_all()`.

**Tech Stack:** Flask, SQLAlchemy, Jinja2 (Bootstrap 5), pytest, SQLite (tests), PostgreSQL (prod)

---

## File Map

| File | Change |
|---|---|
| `app/models.py` | Add `notes` (Text) and `notes_updated_at` (DateTime) to `Alert` |
| `migrations/add_notes_to_alerts.sql` | CREATE — one-time ALTER TABLE for existing DBs |
| `app/dashboard/routes.py` | Add `update_alert_notes` route |
| `app/dashboard/templates/alert_detail.html` | Insert notes form between status form and triggering events |
| `tests/test_notes.py` | CREATE — 8 tests covering POST, GET, max-length, XSS |

---

## Task 1: Add columns to Alert model and create migration script

**Files:**
- Modify: `app/models.py`
- Create: `migrations/add_notes_to_alerts.sql`

- [ ] **Step 1: Add the two columns to the Alert model**

Open `app/models.py`. Find the `Alert` class and add the two new columns after `details`:

```python
class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    rule_id = db.Column(db.String(64), nullable=False)
    title = db.Column(db.String(256), nullable=False)
    severity = db.Column(db.String(16), nullable=False)
    attack_technique = db.Column(db.String(32), nullable=False)
    attack_tactic = db.Column(db.String(64), nullable=False)
    host = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(16), nullable=False, default="new")
    triggering_event_ids = db.Column(db.JSON, nullable=False)
    details = db.Column(db.JSON, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    notes_updated_at = db.Column(db.DateTime, nullable=True)
```

- [ ] **Step 2: Create the migrations directory and SQL migration script**

Create a new file `migrations/add_notes_to_alerts.sql` with this content:

```sql
-- Run once against existing installations to add triage notes columns.
-- Fresh installs pick these up automatically via db.create_all().
ALTER TABLE alerts ADD COLUMN notes TEXT;
ALTER TABLE alerts ADD COLUMN notes_updated_at TIMESTAMP;
```

- [ ] **Step 3: Verify existing tests still pass**

Run the full suite to confirm the new nullable columns don't break anything:

```
venv/Scripts/python -m pytest -v
```

Expected: all existing tests pass (currently 81). The new columns are nullable so no existing fixtures or inserts break.

- [ ] **Step 4: Commit**

```bash
git add app/models.py migrations/add_notes_to_alerts.sql
git commit -m "feat: add notes and notes_updated_at columns to Alert model"
```

---

## Task 2: POST route with TDD (auth redirect, save, overwrite, empty, max-length)

**Files:**
- Create: `tests/test_notes.py`
- Modify: `app/dashboard/routes.py`

- [ ] **Step 1: Create the test file with fixtures and the first 5 POST tests**

Create `tests/test_notes.py`:

```python
import pytest
from app import create_app
from app.db import db
from app.models import Alert


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def authed_app():
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
    """Unauthenticated test client for the auth-enabled app."""
    return authed_app.test_client()


@pytest.fixture
def logged_in_client(authed_app):
    """Test client that has already POSTed to /login."""
    client = authed_app.test_client()
    client.post("/login", data={"username": "admin", "password": "secret"})
    return client


@pytest.fixture
def alert_id(authed_app):
    """Create a minimal Alert in the test DB and return its id."""
    alert = Alert(
        rule_id="RULE-001",
        title="Test Alert",
        severity="medium",
        attack_technique="T1110",
        attack_tactic="Credential Access",
        host="test-host",
        triggering_event_ids=[1],
    )
    db.session.add(alert)
    db.session.commit()
    return alert.id


# ── POST route tests ──────────────────────────────────────────────────────────

def test_unauthenticated_post_redirects_to_login(authed_client, alert_id):
    response = authed_client.post(f"/alerts/{alert_id}/notes", data={"notes": "hi"})
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_save_note_sets_notes_and_timestamp(logged_in_client, authed_app, alert_id):
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": "test note"})
    db.session.expire_all()
    alert = Alert.query.get(alert_id)
    assert alert.notes == "test note"
    assert alert.notes_updated_at is not None


def test_overwrite_note_replaces_previous(logged_in_client, authed_app, alert_id):
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": "first"})
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": "second"})
    db.session.expire_all()
    alert = Alert.query.get(alert_id)
    assert alert.notes == "second"


def test_save_empty_note_clears_text_but_sets_timestamp(logged_in_client, authed_app, alert_id):
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": "something"})
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": ""})
    db.session.expire_all()
    alert = Alert.query.get(alert_id)
    assert alert.notes == ""
    assert alert.notes_updated_at is not None


def test_max_length_guard_rejects_note_over_2000_chars(logged_in_client, authed_app, alert_id):
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": "initial"})
    response = logged_in_client.post(
        f"/alerts/{alert_id}/notes",
        data={"notes": "x" * 2001},
        follow_redirects=False,
    )
    assert response.status_code == 302
    db.session.expire_all()
    alert = Alert.query.get(alert_id)
    assert alert.notes == "initial"  # unchanged
```

- [ ] **Step 2: Run these tests to confirm they all fail (route doesn't exist yet)**

```
venv/Scripts/python -m pytest tests/test_notes.py -v
```

Expected: all 5 tests FAIL — `werkzeug.routing.exceptions.BuildError` or 404 because `update_alert_notes` route doesn't exist yet.

- [ ] **Step 3: Add the update_alert_notes route to app/dashboard/routes.py**

Open `app/dashboard/routes.py`. Add this route after the existing `update_alert_status` route (around line 59):

```python
@dashboard_bp.route("/alerts/<int:alert_id>/notes", methods=["POST"])
@login_required
def update_alert_notes(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    note = request.form.get("notes", "")
    if len(note) > 2000:
        flash("Note is too long. Maximum 2000 characters.")
        return redirect(url_for("dashboard.alert_detail", alert_id=alert_id))
    alert.notes = note
    alert.notes_updated_at = datetime.utcnow()
    db.session.commit()
    return redirect(url_for("dashboard.alert_detail", alert_id=alert_id))
```

Note: `datetime` is already imported at the top of `routes.py` (`from datetime import datetime, timedelta`). No new imports needed.

- [ ] **Step 4: Run the 5 POST tests to confirm they all pass**

```
venv/Scripts/python -m pytest tests/test_notes.py -v
```

Expected: all 5 tests PASS.

- [ ] **Step 5: Run the full suite to confirm no regressions**

```
venv/Scripts/python -m pytest -v
```

Expected: all tests pass (81 existing + 5 new = 86 total).

- [ ] **Step 6: Commit**

```bash
git add tests/test_notes.py app/dashboard/routes.py
git commit -m "feat: add POST /alerts/<id>/notes route with max-length guard (TDD)"
```

---

## Task 3: Template changes and GET tests (show note, show timestamp, XSS safety)

**Files:**
- Modify: `app/dashboard/templates/alert_detail.html`
- Modify: `tests/test_notes.py`

- [ ] **Step 1: Add the 3 GET tests to tests/test_notes.py**

Append these three tests to the bottom of `tests/test_notes.py`:

```python
# ── GET / template rendering tests ───────────────────────────────────────────

def test_detail_page_shows_saved_note(logged_in_client, alert_id):
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": "my findings"})
    response = logged_in_client.get(f"/alerts/{alert_id}")
    assert response.status_code == 200
    assert b"my findings" in response.data


def test_detail_page_shows_last_updated_when_note_saved(logged_in_client, alert_id):
    logged_in_client.post(f"/alerts/{alert_id}/notes", data={"notes": "check"})
    response = logged_in_client.get(f"/alerts/{alert_id}")
    assert b"Last updated" in response.data


def test_xss_note_is_html_escaped_in_template(logged_in_client, alert_id):
    logged_in_client.post(
        f"/alerts/{alert_id}/notes",
        data={"notes": "<script>alert(1)</script>"},
    )
    response = logged_in_client.get(f"/alerts/{alert_id}")
    assert b"<script>alert(1)</script>" not in response.data
    assert b"&lt;script&gt;" in response.data
```

- [ ] **Step 2: Run the 3 new GET tests to confirm they fail**

```
venv/Scripts/python -m pytest tests/test_notes.py::test_detail_page_shows_saved_note tests/test_notes.py::test_detail_page_shows_last_updated_when_note_saved tests/test_notes.py::test_xss_note_is_html_escaped_in_template -v
```

Expected: all 3 FAIL — the template doesn't have the notes form yet so none of the assertions can pass.

- [ ] **Step 3: Insert the notes form into alert_detail.html**

Open `app/dashboard/templates/alert_detail.html`. The current file ends the status form block at line 22 (`</form>`) and then has `<h3>Triggering Events</h3>` at line 24.

Insert the notes form between the closing `</form>` of the status block and the `<h3>Triggering Events</h3>` heading. The full updated file should look like this:

```html
{% extends "base.html" %}
{% block title %}Alert Detail{% endblock %}
{% block content %}
<h2>{{ alert.title }}</h2>
<table class="table table-bordered w-auto">
    <tr><th>Severity</th><td>{{ alert.severity }}</td></tr>
    <tr><th>ATT&amp;CK Technique</th><td>{{ alert.attack_technique }}</td></tr>
    <tr><th>ATT&amp;CK Tactic</th><td>{{ alert.attack_tactic }}</td></tr>
    <tr><th>Host</th><td>{{ alert.host }}</td></tr>
    <tr><th>Created</th><td>{{ alert.created_at.strftime("%Y-%m-%d %H:%M:%S") }}</td></tr>
    <tr><th>Details</th><td>{{ (alert.details or {}) | tojson }}</td></tr>
</table>

<form method="post" action="{{ url_for('dashboard.update_alert_status', alert_id=alert.id) }}" class="mb-4">
    <label for="status">Status:</label>
    <select name="status" id="status">
        {% for value, label in [("new", "New"), ("in_progress", "In Progress"), ("closed_tp", "Closed - True Positive"), ("closed_fp", "Closed - False Positive")] %}
        <option value="{{ value }}" {% if alert.status == value %}selected{% endif %}>{{ label }}</option>
        {% endfor %}
    </select>
    <button type="submit" class="btn btn-primary btn-sm">Update</button>
</form>

<form method="post" action="{{ url_for('dashboard.update_alert_notes', alert_id=alert.id) }}" class="mb-4">
    <label for="notes" class="form-label">Analyst Notes</label>
    <textarea name="notes" id="notes" class="form-control mb-2" rows="4" maxlength="2000">{{ alert.notes or "" }}</textarea>
    <div class="d-flex align-items-center gap-3">
        <button type="submit" class="btn btn-success btn-sm">Save Note</button>
        {% if alert.notes_updated_at %}
        <small class="text-muted">Last updated: {{ alert.notes_updated_at.strftime("%Y-%m-%d %H:%M") }}</small>
        {% endif %}
    </div>
</form>

<h3>Triggering Events</h3>
<table class="table table-sm">
    <thead>
        <tr><th>Time</th><th>Event Type</th><th>User</th><th>Source IP</th><th>Raw</th></tr>
    </thead>
    <tbody>
        {% for event in events %}
        <tr>
            <td>{{ event.timestamp.strftime("%Y-%m-%d %H:%M:%S") }}</td>
            <td>{{ event.event_type }}</td>
            <td>{{ event.user or "" }}</td>
            <td>{{ event.src_ip or "" }}</td>
            <td><code>{{ event.raw or "" }}</code></td>
        </tr>
        {% endfor %}
    </tbody>
</table>
<a href="{{ url_for('dashboard.alert_feed') }}">&larr; Back to alerts</a>
{% endblock %}
```

- [ ] **Step 4: Run the 3 GET tests to confirm they pass**

```
venv/Scripts/python -m pytest tests/test_notes.py::test_detail_page_shows_saved_note tests/test_notes.py::test_detail_page_shows_last_updated_when_note_saved tests/test_notes.py::test_xss_note_is_html_escaped_in_template -v
```

Expected: all 3 PASS.

- [ ] **Step 5: Run the full suite to confirm no regressions**

```
venv/Scripts/python -m pytest -v
```

Expected: all tests pass (81 existing + 8 new = 89 total).

- [ ] **Step 6: Commit**

```bash
git add app/dashboard/templates/alert_detail.html tests/test_notes.py
git commit -m "feat: add analyst notes form to alert detail page (TDD)"
```

---

## Verification

After all three tasks are complete:

1. Run `venv/Scripts/python -m pytest -v` — expect 89 tests, all green.
2. Start the app: `docker-compose up` (or `venv/Scripts/python -m flask run` with a local Postgres).
3. Log in, open any alert detail page.
4. Type a note in the textarea and click "Save Note" — page reloads, note is pre-filled, "Last updated" timestamp appears.
5. Change the status dropdown — note text is unaffected (separate form).
6. Overwrite the note and save again — new text shows, timestamp updates.
