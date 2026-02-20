# graphspy/api/settings.py

# External library imports
from flask import Blueprint, current_app, request

# Local library imports
from ..core import user_agent as ua
from ..db import connection

bp = Blueprint("settings_", __name__)


@bp.post("/api/set_table_error_messages")
def set_table_error_messages():
    state = request.form.get("state")
    if state not in ["enabled", "disabled"]:
        return f"[Error] Invalid state '{state}'.", 400
    current_app.config["table_error_messages"] = state
    return f"[Success] {state.capitalize()} datatable error messages."


@bp.get("/api/get_settings")
def get_settings():
    rows = connection.query_db_json("SELECT * FROM settings")
    return {row["setting"]: row["value"] for row in rows}


@bp.get("/api/get_user_agent")
def get_user_agent():
    return ua.get()


@bp.post("/api/set_user_agent")
def set_user_agent():
    user_agent = request.form.get("user_agent", "")
    if not user_agent:
        return "[Error] User agent not specified!", 400
    if not ua.set(user_agent):
        return f"[Error] Unable to set user agent to '{user_agent}'!", 400
    return f"[Success] User agent set to '{user_agent}'!"
