import os
from flask import Flask
from app.db import db


def create_app(config=None):
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///siem.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    if config:
        app.config.update(config)

    db.init_app(app)

    from app import models  # noqa: F401 - registers tables with SQLAlchemy
    from app.ingest import ingest_bp
    app.register_blueprint(ingest_bp)

    with app.app_context():
        db.create_all()

    if not app.config.get("TESTING"):
        from app.scheduler import start_background_loop
        start_background_loop(app)

    return app
