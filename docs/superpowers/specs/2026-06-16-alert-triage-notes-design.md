# Alert Triage Notes — Design Spec

## 1. Goal

Add a freetext analyst notes field to the alert detail page. When triaging an alert, the analyst can type investigation findings, save them, and see them on every subsequent visit. This completes the triage workflow alongside the existing status dropdown.

## 2. Data Model

Two new nullable columns on the existing `alerts` table. No new table.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `notes` | `TEXT` | yes | Analyst freetext. Overwritten on each save. `NULL` until first save. |
| `notes_updated_at` | `TIMESTAMP` | yes | Set to `utcnow()` on each save. `NULL` until first save. |

### Migration

Existing installs require a one-time migration script:

```sql
-- migrations/add_notes_to_alerts.sql
ALTER TABLE alerts ADD COLUMN notes TEXT;
ALTER TABLE alerts ADD COLUMN notes_updated_at TIMESTAMP;
```

Fresh installs pick up the columns automatically via `db.create_all()`.

## 3. Routes

One new route added to `app/dashboard/routes.py`, mirroring the existing `update_alert_status` pattern:

```
POST /alerts/<int:alert_id>/notes
```

- Protected by `@login_required`
- Reads `request.form["notes"]`
- Rejects notes longer than 2000 characters: flashes an error and redirects back (no DB write)
- Sets `alert.notes` and `alert.notes_updated_at = datetime.utcnow()`
- Commits and redirects to `dashboard.alert_detail`

The existing `GET /alerts/<id>` route needs no changes — `alert.notes` and `alert.notes_updated_at` are available on the model automatically.

## 4. Template Changes

One insertion in `app/dashboard/templates/alert_detail.html`, between the status form and the "Triggering Events" heading:

```html
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
```

No other template files change.

## 5. Testing

New file `tests/test_notes.py`. Uses the same `authed_client` fixture pattern as `tests/test_auth.py` (app configured with `DASHBOARD_PASSWORD="secret"`, logged-in test client).

| # | Test | Assertion |
|---|---|---|
| 1 | Unauthenticated POST redirects | `POST /alerts/1/notes` without login → 302 to `/login` |
| 2 | Save note | POST `notes="test note"` → 302, `alert.notes == "test note"`, `notes_updated_at` is not None |
| 3 | Overwrite note | Save twice → second value wins, `notes_updated_at` updated |
| 4 | Save empty note | POST `notes=""` → `alert.notes == ""`, `notes_updated_at` set |
| 5 | Detail page shows note | `GET /alerts/<id>` with saved note → response body contains note text |
| 6 | Detail page shows timestamp | Response contains "Last updated" when `notes_updated_at` is set |
| 7 | Max-length guard | POST `notes` with 2001-char string → 302 redirect, `alert.notes` unchanged, flash message present |
| 8 | XSS render safety | Save `notes="<script>alert(1)</script>"` → GET detail response contains `&lt;script&gt;` (Jinja2 auto-escape), not the raw tag |

Existing tests are unaffected — the new columns are nullable, so no existing fixtures break.

## 6. Out of Scope

- Append-only comment threads (separate `AlertNote` table) — not needed for this portfolio use case
- Per-note authorship — single admin user, no multi-user support
- Note history / undo
