# graphspy/api/refresh_tokens.py

# Built-in imports
import traceback
import json

# External library imports
from flask import Blueprint, redirect, request

# Local library imports
from ..db import connection
from ..core import tokens

bp = Blueprint("refresh_tokens", __name__)


@bp.get("/api/list_refresh_tokens")
def list_refresh_tokens():
    rows = connection.query_db_json("SELECT * FROM refreshtokens")
    return json.dumps(rows)


@bp.get("/api/get_refresh_token/<id>")
def get_refresh_token(id):
    row = connection.query_db_json(
        "SELECT * FROM refreshtokens WHERE id = ?", [id], one=True
    )
    return json.dumps(row)


@bp.post("/api/add_refresh_token")
def add_refresh_token():
    refreshtoken = request.form.get("refreshtoken", "")
    user = request.form.get("user", "")
    tenant = request.form.get("tenant_domain", "")
    resource = request.form.get("resource", "")
    description = request.form.get("description", "")
    foci = 1 if "foci" in request.form else 0
    client_id = request.form.get("client_id", "d3590ed6-52b3-4102-aeff-aad2292ab01c")
    if refreshtoken and tenant and resource:
        tokens.save_refresh_token(
            refreshtoken, description, user, tenant, resource, foci, client_id
        )
    return redirect("/refresh_tokens")


@bp.post("/api/refresh_to_access_token")
def refresh_to_access_token():

    refresh_token_id = request.form.get("refresh_token_id", "")
    client_id = request.form.get("client_id", "defined_in_token")
    resource = request.form.get("resource", "defined_in_token")
    scope = (
        request.form.get("scope")
        or "https://graph.microsoft.com/.default openid offline_access"
    )
    api_version = int(request.form.get("api_version", 1))
    api_version = api_version if api_version in [1, 2] else 1
    store_refresh_token = "store_refresh_token" in request.form
    try:
        result = tokens.refresh_to_access_token(
            refresh_token_id,
            client_id,
            resource,
            scope,
            store_refresh_token,
            api_version,
        )
        status_code = 200 if isinstance(result, int) and result != 0 else 400
        return f"{result}", status_code
    except Exception as e:
        traceback.print_exc()
        return f"[Error] Unexpected error occurred. Exception: {repr(e)}", 400


@bp.get("/api/delete_refresh_token/<id>")
def delete_refresh_token(id):
    connection.execute_db("DELETE FROM refreshtokens WHERE id = ?", [id])
    return "true"


@bp.get("/api/active_refresh_token/<id>")
def set_active_refresh_token(id):
    existing = connection.query_db(
        "SELECT value FROM settings WHERE setting = 'active_refresh_token_id'", one=True
    )
    if not existing:
        connection.execute_db(
            "INSERT INTO settings (setting, value) VALUES ('active_refresh_token_id', ?)",
            (id,),
        )
    else:
        connection.execute_db(
            "UPDATE settings SET value = ? WHERE setting = 'active_refresh_token_id'",
            (id,),
        )
    return id


@bp.get("/api/active_refresh_token")
def get_active_refresh_token():
    row = connection.query_db(
        "SELECT value FROM settings WHERE setting = 'active_refresh_token_id'", one=True
    )
    return f"{row[0]}" if row else "0"
