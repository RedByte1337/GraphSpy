# graphspy/app.py

# External library imports
from flask import Flask

# Local library imports
from . import api, web
from .db import connection


def create_app(db_path: str, db_folder: str, debug: bool = False) -> Flask:
    app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
    app.config["graph_spy_db_path"] = db_path
    app.config["graph_spy_db_folder"] = db_folder
    app.config["table_error_messages"] = "disabled"

    api.register_blueprints(app)
    web.register_blueprint(app)
    app.teardown_appcontext(connection.close)

    return app
