# Dashboard Authentication — Design Spec

## 1. Goal

Add a login gate to the SIEM dashboard so it is no longer open to anyone who can reach the server. Target audience: hiring managers and interviewers doing a live demo. Auth must exist and look credible; it does not need to be production-hardened or multi-tenant.

## 2. Scope

- **In scope:** Flask-Login session auth for all dashboard UI routes; `X-Api-Key` guard on `/api/alerts`; login/logout pages; `validate.py` update.
- **Out of scope:** user registration, password reset, multi-user RBAC, token-based auth, OAuth.

## 3. Credentials

Single admin user. No user table in the database.

| Config key | Source | Notes |
|---|---|---|
| `DASHBOARD_USER` | env var | Defaults to `"admin"` if not set |
| `DASHBOARD_PASSWORD` | env var | If not set, auth is **disabled** (dev/test convenience, same pattern as `INGEST_API_KEY`) |
| `SECRET_KEY` | env var | Required when auth is enabled; used by Flask to sign session cookies |

`docker-compose.yml` exposes these vars so they are visible and self-documenting in the demo setup.

## 4. Architecture

### 4.1 New module: `app/auth.py`

Responsibilities:
- Initialise `flask_login.LoginManager` and attach it to the app.
- Define an in-memory `User` class implementing `flask_login.UserMixin` (single instance, no DB).
- Provide `user_loader` callback that returns the admin user when `user_id == "admin"`.
- Expose an `auth_bp` Blueprint with two routes:
  - `GET /login` — render `login.html`
  - `POST /login` — validate credentials, set session, redirect to `next` or `/`
  - `GET /logout` — `logout_user()`, redirect to `/login`
- Export an `init_auth(app)` function called from `create_app`.

### 4.2 Changes to `app/__init__.py`

- Call `init_auth(app)` after `db.init_app(app)`.
- Register `auth_bp`.
- Add `SECRET_KEY` to app config from env var (Flask already reads `SECRET_KEY` by name, so `app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")`).

### 4.3 Changes to `app/dashboard/routes.py`

- Import `login_required` from `flask_login`.
- Decorate `alert_feed`, `alert_detail`, `update_alert_status`, `heatmap`, `event_explorer` with `@login_required`.
- **Do not** add `@login_required` to `api_alerts`.
- Add `X-Api-Key` guard to `api_alerts` — same logic as `/ingest`: if `INGEST_API_KEY` is configured, require the header; if not configured, allow through.

### 4.4 New template: `app/dashboard/templates/login.html`

Extends `base.html`. Centered card (Bootstrap 5), username + password fields, submit button. Flash message area for "Invalid username or password." The navbar renders without nav links (user is not authenticated yet).

### 4.5 Changes to `app/dashboard/templates/base.html`

Add a "Logout" link in the navbar, visible only when `current_user.is_authenticated`.

### 4.6 Changes to `attack-lab/validate.py`

Update the `/api/alerts` poll to send `X-Api-Key: <key>` header. Key read from `--api-key` CLI arg or `INGEST_API_KEY` env var; if neither is set, the header is omitted (backwards-compatible with an unprotected endpoint).

## 5. Auth Flow

```
GET /  (unauthenticated)
  → 302 /login?next=%2F

POST /login  (correct creds)
  → login_user(admin_user)
  → 302 /  (or ?next= target)

POST /login  (wrong creds)
  → flash("Invalid username or password.")
  → 200 /login  (re-render with error)

GET /logout
  → logout_user()
  → 302 /login

GET /api/alerts  (INGEST_API_KEY set, no header)
  → 401 {"error": "unauthorized"}

GET /api/alerts  (correct X-Api-Key)
  → 200  (normal response)
```

## 6. Testing

New file `tests/test_auth.py`:

- When `DASHBOARD_PASSWORD` not set: all dashboard routes return 200 without login (auth disabled — existing tests unaffected).
- When `DASHBOARD_PASSWORD` set: unauthenticated `GET /` redirects to `/login`.
- `POST /login` with correct creds: redirects to `/`.
- `POST /login` with wrong creds: returns 200 (re-render), does not set session.
- `GET /logout`: clears session, redirects to `/login`.
- `GET /api/alerts` with `INGEST_API_KEY` set and no header: returns 401.
- `GET /api/alerts` with correct key: returns 200.

Existing tests (`test_app.py`, `test_dashboard.py`, etc.) require zero changes because they do not set `DASHBOARD_PASSWORD` in their `create_app` config.

## 7. Dependencies

Add `flask-login` to `requirements.txt`. No other new packages.

## 8. Files changed / created

| File | Change |
|---|---|
| `app/auth.py` | **new** |
| `app/dashboard/templates/login.html` | **new** |
| `app/__init__.py` | init auth, register blueprint, SECRET_KEY |
| `app/dashboard/routes.py` | @login_required on UI routes; X-Api-Key on /api/alerts |
| `app/dashboard/templates/base.html` | Logout link |
| `attack-lab/validate.py` | send X-Api-Key header |
| `requirements.txt` | add flask-login |
| `docker-compose.yml` | expose DASHBOARD_USER, DASHBOARD_PASSWORD, SECRET_KEY vars |
| `tests/test_auth.py` | **new** |
