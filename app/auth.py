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
