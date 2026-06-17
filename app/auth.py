from flask_login import LoginManager

login_manager = LoginManager()


@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))


def init_auth(app):
    login_manager.login_view = "dashboard.login"
    login_manager.init_app(app)
