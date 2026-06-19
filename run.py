import os

# Dev defaults — set before create_app() reads the environment.
# This block only runs when executed directly (`python run.py`); gunicorn
# imports this module as 'run' so __name__ != '__main__' and the block is
# skipped, leaving the production RuntimeError guards intact.
if __name__ == "__main__":
    os.environ.setdefault("SECRET_KEY", "dev-secret-not-for-production")
    os.environ.setdefault("ALLOW_UNAUTHENTICATED_INGEST", "1")

from app import create_app
from app.cli import ensure_admin

app = create_app({"SESSION_COOKIE_SECURE": False} if __name__ == "__main__" else None)

if __name__ == "__main__":
    # Dev convenience: seed admin/demo so you can log in immediately without
    # running create-admin first. Honors ADMIN_USERNAME / ADMIN_PASSWORD env
    # vars when set (as docker-compose does), falling back to admin/demo for
    # plain local dev. ensure_admin() upserts, so the password is always reset
    # to the default on each local start.
    with app.app_context():
        ensure_admin(
            os.environ.get("ADMIN_USERNAME", "admin"),
            os.environ.get("ADMIN_PASSWORD", "demo"),
        )
    # Development only: Werkzeug's built-in server is single-threaded and
    # not suitable for production. Use gunicorn or uwsgi behind a reverse
    # proxy in production (see docker-compose.yml for the compose setup).
    import subprocess, sys
    if os.environ.get("SIEM_START_FORWARDER") == "1":
        env = os.environ.copy()
        env.setdefault("PYTHONPATH", os.getcwd())
        subprocess.Popen([sys.executable, "forwarders/windows_forwarder.py"], env=env)
    app.run(host="0.0.0.0", port=5000)
