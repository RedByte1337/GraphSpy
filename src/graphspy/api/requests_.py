# graphspy/api/requests_.py

# Built-in imports
import json

# External library imports
from flask import Blueprint, request
from loguru import logger

# Local library imports
from ..core import requests_ as generic
from ..db import connection

bp = Blueprint("requests_", __name__)


@bp.post("/api/generic_graph")
def generic_graph():
    graph_uri = request.form["graph_uri"]
    access_token_id = request.form["access_token_id"]
    method = request.form.get("method", "GET")
    body = json.loads(request.form.get("body") or "{}")
    return generic.graph_request(graph_uri, access_token_id, method, body)


@bp.post("/api/generic_graph_upload")
def generic_graph_upload():
    try:
        upload_uri = request.form["upload_uri"]
        access_token_id = request.form["access_token_id"]
        file = request.files["file"]
        if not upload_uri or not access_token_id or not file:
            return json.dumps({"error": "Missing required parameters"}), 400
        return generic.graph_upload_request(upload_uri, access_token_id, file)
    except Exception as e:
        logger.exception("Error in generic_graph_upload")
        return json.dumps({"error": "Internal server error.", "details": str(e)}), 500


@bp.post("/api/custom_api_request")
def custom_api_request():
    if not request.is_json:
        return "[Error] Expecting JSON input.", 400
    data = request.get_json()
    uri = data.get("uri", "")
    access_token_id = data.get("access_token_id", 0)
    method = data.get("method", "GET")
    request_type = data.get("request_type", "text")
    body = data.get("body", "")
    headers = data.get("headers", {})
    variables = data.get("variables", {})
    if not (uri and access_token_id and method):
        return "[Error] URI, Access Token ID and Method are mandatory!", 400
    if request_type not in ["text", "json", "urlencoded", "xml"]:
        return f"[Error] Invalid request type '{request_type}'.", 400
    if not isinstance(headers, dict) or not isinstance(variables, dict):
        return "[Error] Expecting JSON for headers and variables.", 400
    for var_name, var_value in variables.items():
        uri = uri.replace(var_name, var_value)
        body = body.replace(var_name, var_value)
        headers = {
            (k.replace(var_name, var_value) if isinstance(k, str) else k): (
                v.replace(var_name, var_value) if isinstance(v, str) else v
            )
            for k, v in headers.items()
        }
    try:
        return generic.make_request(
            uri, access_token_id, method, request_type, body, headers
        )
    except Exception as e:
        logger.exception("Error in custom_api_request")
        return f"[Error] Unexpected error. Exception: {repr(e)}", 400


@bp.post("/api/save_request_template")
def save_request_template():
    if not request.is_json:
        return "[Error] Expecting JSON input.", 400
    data = request.get_json()
    template_name = data.get("template_name", "")
    uri = data.get("uri", "")
    method = data.get("method", "GET")
    request_type = data.get("request_type", "text")
    body = data.get("body", "")
    headers = data.get("headers", {})
    variables = data.get("variables", {})
    if not (template_name and uri and method):
        return "[Error] Template Name, URI and Method are mandatory!", 400
    if request_type not in ["text", "json", "urlencoded", "xml"]:
        return f"[Error] Invalid request type '{request_type}'.", 400
    if not isinstance(headers, dict) or not isinstance(variables, dict):
        return "[Error] Expecting JSON for headers and variables.", 400
    try:
        existing = connection.query_db_json(
            "SELECT * FROM request_templates WHERE template_name = ?",
            [template_name],
            one=True,
        )
        if existing:
            connection.execute_db(
                "DELETE FROM request_templates WHERE id = ?", [existing["id"]]
            )
        connection.execute_db(
            "INSERT INTO request_templates (template_name, uri, method, request_type, body, headers, variables) VALUES (?,?,?,?,?,?,?)",
            (
                template_name,
                uri,
                method,
                request_type,
                body,
                json.dumps(headers),
                json.dumps(variables),
            ),
        )
        return f"[Success] {'Updated' if existing else 'Saved'} template '{template_name}'."
    except Exception as e:
        logger.exception("Error in save_request_template")
        return f"[Error] Unexpected error. Exception: {repr(e)}", 400


@bp.get("/api/get_request_templates/<template_id>")
def get_request_template(template_id):
    row = connection.query_db_json(
        "SELECT * FROM request_templates WHERE id = ?", [template_id], one=True
    )
    if not row:
        return f"[Error] Unable to find request template with ID '{template_id}'.", 400
    row["headers"] = json.loads(row["headers"])
    row["variables"] = json.loads(row["variables"])
    return row


@bp.get("/api/list_request_templates")
def list_request_templates():
    rows = connection.query_db_json("SELECT * FROM request_templates")
    for row in rows:
        row["headers"] = json.loads(row["headers"])
        row["variables"] = json.loads(row["variables"])
    return rows


@bp.post("/api/delete_request_template")
def delete_request_template():
    template_id = request.form.get("template_id")
    if not template_id:
        return "[Error] No template_id specified.", 400
    existing = connection.query_db_json(
        "SELECT * FROM request_templates WHERE id = ?", [template_id], one=True
    )
    if not existing:
        return f"[Error] Unable to find request template with ID '{template_id}'.", 400
    connection.execute_db("DELETE FROM request_templates WHERE id = ?", [template_id])
    return f"[Success] Deleted request template '{existing['template_name']}'."
