from app import create_app

app = create_app()

if __name__ == "__main__":
    # Development only: Werkzeug's built-in server is single-threaded and
    # not suitable for production. Use gunicorn or uwsgi behind a reverse
    # proxy in production (see docker-compose.yml for the compose setup).
    app.run(host="0.0.0.0", port=5000)
