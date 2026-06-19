# Running the SIEM with Docker

This guide explains Docker from scratch using **this project's actual files**.
By the end you'll understand every line of `Dockerfile` and `docker-compose.yml`
and be able to run the full stack (Flask app + PostgreSQL) with a single command.

---

## 1. What is Docker?

Normally, to run this app you need:
- Python 3.12 installed
- `pip install -r requirements.txt`
- PostgreSQL running somewhere

If a colleague (or a server) doesn't have those exact versions, it breaks.

Docker packages **your app + Python + every dependency** into a sealed box
called an **image**. When you run that image you get a **container** — an
isolated mini-computer that behaves identically everywhere: your laptop, a
Linux server, CI/CD.

Three words to know:

| Term | What it is | Analogy |
|------|-----------|---------|
| **Image** | Frozen blueprint — built once | A recipe |
| **Container** | A running instance of an image | A dish made from the recipe |
| **Volume** | A named folder that outlives containers | A USB drive plugged into the container |

---

## 2. Your three Docker files

### `Dockerfile` — how to build the app image

```dockerfile
FROM python:3.12-slim
```
Start from an official slim Linux image that has Python 3.12.
`slim` = no extras, just what Python needs. Smaller image = faster.

```dockerfile
WORKDIR /app
```
Create `/app` inside the container and use it as the working directory for all
following commands. Like `cd /app` that sticks.

```dockerfile
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
```
Copy the requirements file first, then install. This is a **layer caching trick**.
Docker caches each step. If you only change your Python code (not requirements),
the next `docker build` skips the slow `pip install` and reuses the cached layer.
Always copy deps before code.

```dockerfile
COPY . .
```
Now copy all your app code in. This runs after pip, so changing code doesn't
bust the pip cache.

```dockerfile
RUN useradd --create-home --uid 1000 appuser \
    && chown -R appuser:appuser /app
USER appuser
```
Create a non-root user and switch to it. Containers run as root by default, which
is a security risk. If something in the container is exploited, a non-root user
limits the blast radius.

```dockerfile
EXPOSE 5000
```
Document that this container listens on port 5000. Doesn't actually open anything —
that's done in `docker-compose.yml`. Think of it as a note.

```dockerfile
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "run:app"]
```
The default command when the container starts. Runs gunicorn (production-grade
server) instead of Flask's built-in dev server. `run:app` tells gunicorn to import
the `app` object from `run.py`.

---

### `docker-compose.yml` — run two containers together

Your SIEM needs two things: the Flask app **and** PostgreSQL. Compose starts both
with one command and wires them together on a private network.

```yaml
services:
  db:
    image: postgres:16
```
Pull the official PostgreSQL 16 image from Docker Hub. No `Dockerfile` needed
for the database — the official image handles everything.

```yaml
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-siem}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env}
      POSTGRES_DB: ${POSTGRES_DB:-siem}
```
Environment variables configure PostgreSQL on first start. The `:?` syntax means
"fail loudly if this is empty" — Compose will refuse to start if you forget
`POSTGRES_PASSWORD`. The `:-siem` syntax means "default to 'siem' if not set".

```yaml
    volumes:
      - pgdata:/var/lib/postgresql/data
```
Mount the named volume `pgdata` at PostgreSQL's data directory. This means your
events, alerts, and rules **survive** `docker compose down`. Without this, every
restart would wipe the database.

```yaml
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-siem}"]
      interval: 5s
      timeout: 5s
      retries: 5
```
Poll every 5 seconds until PostgreSQL is actually ready to accept connections.
Without this, the app container might start and try to connect before the DB is
up — a race condition. The `depends_on` below uses this healthcheck.

```yaml
  app:
    build: .
```
Build an image using `./Dockerfile` (the `.` means "current directory"). This is
what reads your `Dockerfile` and runs all those steps.

```yaml
    environment:
      DATABASE_URL: postgresql://${POSTGRES_USER:-siem}:${POSTGRES_PASSWORD:?...}@db:5432/${POSTGRES_DB:-siem}
```
`@db:5432` — notice `db` is the **name of the other service**. Compose creates a
private network where services can reach each other by name. The app container
talks to `db:5432` without knowing the host machine's IP.

```yaml
    ports:
      - "5000:5000"
```
Map the host's port 5000 → the container's port 5000. Format: `"host:container"`.
This is what makes http://localhost:5000 work from your browser.

```yaml
    depends_on:
      db:
        condition: service_healthy
```
Don't start the app until `db` passes its healthcheck. This is the gate that
prevents the race condition.

```yaml
    command: >
      sh -c "flask --app run create-admin && python run.py"
```
Override the Dockerfile's `CMD`. On first start, create the admin user, then
start the app. The `>` is YAML multi-line syntax — it's all one string.

```yaml
volumes:
  pgdata:
```
Declare the named volume. Docker manages its lifecycle. It persists even after
`docker compose down`. Only destroyed with `docker compose down -v` (careful!).

---

### `.dockerignore` — what NOT to copy into the image

Just like `.gitignore`. Key exclusions in this project:
- `venv/` — never put your local virtualenv in the image; the Dockerfile creates
  its own Python environment via `pip install`.
- `.env` — your secrets. Never bake secrets into an image. Pass them via
  environment variables at runtime.
- `data/` — large log sample files used for testing. No need in production.
- `__pycache__/` — Python bytecode that's OS-specific and regenerated anyway.

---

## 3. Running it

### Prerequisites
- Docker Desktop installed and running ("Engine running" in the system tray)

### One-time setup

**Step 1 — copy the env file:**
```bash
cp .env.example .env
```

**Step 2 — fill in the four required secrets.** Open `.env` and set:

```
POSTGRES_PASSWORD=<generate below>
SECRET_KEY=<generate below>
ADMIN_PASSWORD=<generate below>
INGEST_API_KEY=<generate below>
```

Generate each with:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```
Run that four times and paste each output into `.env`. These are random 64-char
hex strings. Keep the file private — it's gitignored.

**Step 3 — build and start:**
```powershell
docker compose up -d
```

What happens:
1. Docker builds the `app` image layer by layer (slow first time, fast after)
2. `db` starts, PostgreSQL initialises
3. Healthcheck polls until `db` is ready
4. `app` starts, creates the admin user, then gunicorn launches

The `-d` flag runs everything in the background so you get your terminal back.
Open http://localhost:5000 and log in with `admin` and the `ADMIN_PASSWORD` you set.

**Step 4 — every time after that, use Docker Desktop.**
Open the **Containers** tab, find the `cyber` stack, and click ▶ to start or
■ to stop. No terminal needed after the first run — Docker Desktop remembers
the compose config and env vars.

> **Do not use the "Run" button on the image in Docker Desktop.** That button
> starts the image in isolation without `docker-compose.yml` or `.env`, so
> env vars like `SECRET_KEY` are missing and the app crashes with
> `RuntimeError: SECRET_KEY is not set`. Always use the Containers tab or
> `docker compose up -d` from the terminal.

---

## 4. Daily commands

| Command | What it does |
|---------|-------------|
| `docker compose up --build` | Build (if changed) and start everything, logs in foreground |
| `docker compose up -d` | Start in background (detached) |
| `docker compose down` | Stop and remove containers. Data is safe (volume persists) |
| `docker compose down -v` | **Deletes the database volume too** — all data gone. Use to reset. |
| `docker compose ps` | Show running containers and their status |
| `docker compose logs -f app` | Tail the app logs live |
| `docker compose logs -f db` | Tail the database logs live |
| `docker compose exec app bash` | Open a shell inside the running app container |
| `docker compose build` | Rebuild the image without starting |

---

## 5. Verify it's working

After `docker compose up`, in a new terminal:

```bash
docker compose ps
```

Both services should show `running` (db) and `running` (app). The db service
should also show `(healthy)`.

```bash
docker compose logs app | grep "Listening at"
```

You should see gunicorn reporting it's listening on `0.0.0.0:5000`.

Then open http://localhost:5000 — the dashboard should load.

---

## 6. Troubleshooting

**`RuntimeError: SECRET_KEY is not set` on startup**
You ran the image directly from Docker Desktop's "Images" tab using the Run
button. That bypasses `docker-compose.yml` and `.env`, so no env vars are
injected. Fix: use the **Containers** tab (▶ to start) or run
`docker compose up -d` from a terminal in the repo folder.

**"Cannot connect to the Docker daemon"**
Docker Desktop isn't running. Open Docker Desktop and wait for "Engine running."

**Port 5000 already in use**
Something else (maybe `python run.py`) is using port 5000. Stop it, or change
the host port in `docker-compose.yml` from `"5000:5000"` to e.g. `"5001:5000"`
and visit http://localhost:5001 instead.

**Port 5432 already in use**
A local PostgreSQL is running. Stop it (`pg_ctl stop`) or change the db ports
line to `"5433:5432"`.

**App exits immediately**
Check `docker compose logs app`. Usually a missing env var — Compose will print
something like `set POSTGRES_PASSWORD in .env`.

**Data missing after restart**
You ran `docker compose down -v`. That wipes the `pgdata` volume. Use plain
`docker compose down` (no `-v`) to preserve data.

---

## 7. How this differs from `python run.py`

| | `python run.py` (local dev) | `docker compose up` (Docker) |
|-|--------------------------|------------------------------|
| Database | SQLite file (`siem.db`) | Real PostgreSQL in a container |
| Server | Flask dev server (single thread) | Gunicorn (2 workers, production-grade) |
| Secrets | Hard-coded dev defaults in `run.py` | Required from `.env` — no defaults |
| Admin user | Seeded automatically (`admin/demo`) | Created from `ADMIN_USERNAME/ADMIN_PASSWORD` |
| Setup | Zero config | One-time `.env` file |

Use `python run.py` for fast local development. Use Docker when you want to
test the production configuration or deploy somewhere.

---

## 8. Monitoring your real Windows machine

### Why the dashboard "Machine Monitor" button doesn't work under Docker

Docker Desktop on Windows runs your containers inside a **Linux VM (WSL2)**.
When the dashboard starts the Machine Monitor it launches `host_forwarder.py`
as a subprocess *inside that Linux container* — so `psutil` sees the VM's
~4 processes, not your Windows machine. There is no way around this: the
Windows process table and Event Log are not accessible from inside a Linux
container.

The fix is simple and matches how real SIEMs work: run the forwarder **on
Windows**, posting to the container's published port. The Docker container
stays as the backend; the forwarder is a lightweight agent on the host.

### Path A — process + network monitoring (easiest, works now)

While `docker compose up -d` is already running:

1. Click **"Download run-monitor.bat"** on the Machine Monitor row in the dashboard.
2. Save the file to the **repo root** (`C:\...\Cyber\`).
3. **Double-click** `run-monitor.bat`.

A console window opens showing:

```
Monitoring YOURPC -> http://localhost:5000   (Ctrl+C to stop)
2026-06-19 12:05:57 INFO baseline: 335 processes, 13 connections (not forwarded)
2026-06-19 12:06:00 INFO sent process_creation: notepad.exe
2026-06-19 12:06:16 INFO sent network_connection: chrome.exe outbound ... -> 142.250.80.46:443
```

Events appear in the dashboard within ~2 seconds. Close the window (or press
Ctrl+C inside it) to stop.

> **Note:** The Machine Monitor badge in the dashboard stays **Stopped** even
> while the `.bat` is running — that's expected. The badge only tracks
> subprocesses launched by the app itself (which can't work inside Docker).
> To confirm events are flowing, open the **Events** page and watch new
> process and network entries appear in real time.

Alternatively, run the PowerShell script directly from the repo:

```powershell
.\run-monitor.ps1
```

### Path B — Sysmon Event Log monitoring (optional, richer telemetry)

`windows_forwarder.py` reads **Windows Event Log** (Sysmon Event ID 1 —
process creation, Event ID 3 — network connection) via the native
`win32evtlog` API. This gives true Event Log data suitable for a "full SIEM"
portfolio demo.

**Prerequisites:**

1. Install [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
   and start it logging to `Microsoft-Windows-Sysmon/Operational`.
2. Install the Windows-specific Python deps:
   ```powershell
   venv\Scripts\pip install -r forwarders\requirements-windows.txt
   ```
   (This adds `pywin32` on top of the existing venv.)

**Run it:**

```powershell
$env:SIEM_URL       = "http://localhost:5000"
$env:INGEST_API_KEY = "<your key from .env>"
venv\Scripts\python forwarders\windows_forwarder.py
```

You can run both Path A and Path B at the same time — they forward different
event shapes and don't conflict.
