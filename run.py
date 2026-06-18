import os

from app import create_app
from app.cli import ensure_admin

app = create_app()

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
    app.run(host="0.0.0.0", port=5000)
