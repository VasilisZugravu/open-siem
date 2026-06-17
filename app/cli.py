import click


def ensure_admin(username, password):
    """Create the admin user if it doesn't exist, or update its password if it does.
    Single-admin model: no user table management beyond this one row."""
    from app.db import db
    from app.models import User

    if not password:
        raise ValueError("Admin password must not be empty")

    user = User.query.filter_by(username=username).first()
    if user is None:
        user = User(username=username)
        db.session.add(user)
    user.set_password(password)
    db.session.commit()
    return user


def register_cli(app):
    @app.cli.command("create-admin")
    @click.option("--username", envvar="ADMIN_USERNAME", default="admin", show_default=True)
    @click.option("--password", envvar="ADMIN_PASSWORD", prompt=True, hide_input=True,
                  confirmation_prompt=True)
    def create_admin(username, password):
        """Create or update the single dashboard admin account."""
        ensure_admin(username, password)
        click.echo(f"Admin user '{username}' created/updated.")
