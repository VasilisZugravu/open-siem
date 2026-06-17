from flask_login import LoginManager

login_manager = LoginManager()


@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    try:
        return User.query.get(int(user_id))
    except (TypeError, ValueError):
        # Stale/forged session cookies (e.g. pre-migration sessions that
        # stored the literal string "admin") should look logged-out, not 500.
        return None


def init_auth(app):
    login_manager.login_view = "dashboard.login"
    login_manager.init_app(app)
