# graphspy/app.py

# Built-in imports
import logging

# External library imports
from flask import Flask, jsonify, request
from loguru import logger

# Local library imports
from .core.errors import AppError
from .db import connection


def create_app(db_path: str, db_folder: str) -> Flask:
    app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
    app.config["graph_spy_db_path"] = db_path
    app.config["graph_spy_db_folder"] = db_folder
    app.config["table_error_messages"] = "disabled"

    from .api import (
        access_tokens,
        database,
        device_codes,
        devices,
        entra,
        mfa,
        refresh_tokens,
        requests_,
        settings,
        teams,
    )
    from .web import pages

    for module in [
        access_tokens,
        database,
        device_codes,
        devices,
        entra,
        mfa,
        refresh_tokens,
        requests_,
        settings,
        teams,
        pages,
    ]:
        app.register_blueprint(module.bp)

    @app.after_request
    def log_request(response):
        logger.info(
            f"{response.status_code} {request.method} {request.path} — {request.remote_addr}"
        )
        return response

    @app.errorhandler(AppError)
    def handle_app_error(e):
        logger.error(f"AppError in {e.func_name}():{e.line_number} - {e.message}")
        return jsonify({"message": e.message}), e.status_code

    app.teardown_appcontext(connection.close)

    # Suppress Werkzeug's request logging (duplicate timestamps);
    # requests are logged via after_request above.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    return app
