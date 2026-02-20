# graphspy/web/__init__.py

from .pages import bp


def register_blueprint(app):
    app.register_blueprint(bp)
