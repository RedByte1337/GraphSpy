# graphspy/api/device_codes.py

# External library imports
from flask import Blueprint, request

# Local library imports
from ..core import device_codes
from ..db import connection

bp = Blueprint("device_codes", __name__)


@bp.get("/api/list_device_codes")
def list_device_codes():
    return device_codes.list_device_codes()


@bp.post("/api/restart_device_code_polling")
def restart_device_code_polling():
    return device_codes.start_polling_thread()


@bp.post("/api/generate_device_code")
def generate_device_code():
    version = (
        int(request.form.get("version", "1"))
        if request.form.get("version", "1").isdigit()
        else 1
    )
    client_id = request.form.get("client_id") or "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    resource = request.form.get("resource") or "https://graph.microsoft.com"
    scope = (
        request.form.get("scope")
        or "https://graph.microsoft.com/.default openid offline_access"
    )
    ngcmfa = request.form.get("ngcmfa") == "true"
    cae = request.form.get("cae") == "true"
    auto_action = request.form.get("auto_action")
    if auto_action and auto_action != "none":
        user_code = device_codes.flow(
            version,
            client_id,
            resource,
            scope,
            ngcmfa,
            cae,
            auto_action=auto_action,
            auto_device_name=request.form.get("auto_device_name") or "GraphSpy-Device",
            auto_join_type=int(request.form.get("auto_join_type", 0)),
            auto_device_type=request.form.get("auto_device_type") or "Windows",
            auto_os_version=request.form.get("auto_os_version") or "10.0.26100",
            auto_target_domain=request.form.get("auto_target_domain") or "e-corp.local",
        )
    else:
        user_code = device_codes.flow(version, client_id, resource, scope, ngcmfa, cae)
    return user_code


@bp.get("/api/delete_device_code/<id>")
def delete_device_code(id):
    connection.execute_db("DELETE FROM devicecodes WHERE id = ?", [id])
    return "true"
