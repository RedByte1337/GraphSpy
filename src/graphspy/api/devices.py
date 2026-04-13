# graphspy/api/devices.py

# External library imports
from flask import Blueprint, request

# Local library imports
from ..core import device, prt, winhello
from ..db import connection
from .helpers import create_response

bp = Blueprint("devices", __name__)


@bp.post("/api/register_device")
def register_device():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return create_response(400, "No access_token_id specified.")
    device_id = device.register(
        access_token_id,
        device_name=request.form.get("device_name") or "GraphSpy-Device",
        join_type=int(request.form.get("join_type", 0)),
        device_type=request.form.get("device_type") or "Windows",
        os_version=request.form.get("os_version") or "10.0.26100",
        target_domain=request.form.get("target_domain") or "e-corp.local",
    )
    return create_response(200, f"Successfully registered device {device_id}.", {"device_id": device_id})


@bp.post("/api/import_device_certificate")
def import_device_certificate():
    import base64
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    certificate_base64 = request.form.get("certificate_base64")
    if not certificate_base64:
        return create_response(400, "No certificate_base64 specified.")
    private_key_pem_base64 = request.form.get("private_key_pem_base64")
    if not private_key_pem_base64:
        return create_response(400, "No private_key_pem_base64 specified.")
    device_id = request.form.get("device_id")
    if not device_id:
        try:
            certificate = x509.load_der_x509_certificate(base64.b64decode(certificate_base64))
            device_id = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            return create_response(400, "Invalid certificate format.")
    device_name = request.form.get("device_name") or "GraphSpy-Device"
    device_type = request.form.get("device_type") or "Windows"
    join_type = int(request.form.get("join_type", 0))
    cert_id = connection.execute_db(
        "INSERT INTO device_certificates (stored_at, device_id, device_name, device_type, join_type, priv_key, certificate) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            int(__import__("time").time()), device_id, device_name, device_type,
            "joined" if join_type == 0 else "registered" if join_type == 4 else "unknown",
            private_key_pem_base64, certificate_base64,
        ),
    )
    return create_response(200, f"Added device certificate with ID {cert_id}.", {"device_certificate_id": cert_id})


@bp.get("/api/list_device_certificates")
def list_device_certificates():
    rows = connection.query_db_json("SELECT * FROM device_certificates")
    return create_response(200, data=rows)


@bp.post("/api/delete_device_certificate")
def delete_device_certificate():
    id = request.form.get("id")
    if not id:
        return create_response(400, "No id specified.")
    connection.execute_db("DELETE FROM device_certificates WHERE id = ?", [id])
    return create_response(200, f"Deleted device certificate with ID {id}.")


@bp.post("/api/request_prt_for_device")
def request_prt_for_device():
    device_id = request.form.get("device_id") or connection.query_db(
        "SELECT device_id FROM device_certificates WHERE id = ?", [request.form.get("id")], one=True
    )
    if not device_id:
        return create_response(400, "No device_id or id specified.")
    refresh_token_id = request.form.get("refresh_token_id")
    if not refresh_token_id:
        return create_response(400, "No refresh_token_id specified.")
    os_version = request.form.get("os_version") or "10.0.26100"
    prt_id = prt.request_for_device(device_id, refresh_token_id, os_version)
    return create_response(200, f"Successfully requested PRT with ID {prt_id}.", {"prt_id": prt_id})


@bp.post("/api/import_prt")
def import_prt():
    import time
    from datetime import datetime
    prt_val = request.form.get("prt")
    if not prt_val:
        return create_response(400, "No prt specified.")
    session_key = request.form.get("session_key")
    if not session_key:
        return create_response(400, "No session_key specified.")
    device_id = request.form.get("device_id") or "Unknown"
    user = request.form.get("user") or "Unknown"
    try:
        issued_at = int(request.form.get("issued_at"))
    except (TypeError, ValueError):
        issued_at = None
    try:
        expires_at = int(request.form.get("expires_at"))
    except (TypeError, ValueError):
        expires_at = None
    description = request.form.get("description") or f"Manually added at {str(datetime.now()).split('.')[0]}"
    prt_id = connection.execute_db(
        "INSERT INTO primary_refresh_tokens (device_id, user, prt, session_key, issued_at, expires_at, description) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (device_id, user, prt_val, session_key, issued_at, expires_at, description),
    )
    return create_response(200, f"Added PRT with ID {prt_id}.", {"prt_id": prt_id})


@bp.get("/api/list_primary_refresh_tokens")
def list_primary_refresh_tokens():
    rows = connection.query_db_json("SELECT * FROM primary_refresh_tokens")
    return create_response(200, data=rows)


@bp.get("/api/get_primary_refresh_token/<id>")
def get_primary_refresh_token(id):
    row = connection.query_db_json("SELECT * FROM primary_refresh_tokens WHERE id = ?", [id], one=True)
    if not row:
        return create_response(400, f"No primary refresh token with ID {id} found.")
    return create_response(200, data=row)


@bp.post("/api/delete_primary_refresh_token")
def delete_primary_refresh_token():
    id = request.form.get("id")
    if not id:
        return create_response(400, "No id specified.")
    connection.execute_db("DELETE FROM primary_refresh_tokens WHERE id = ?", [id])
    return create_response(200, f"Deleted primary refresh token with ID {id}.")


@bp.post("/api/refresh_prt_to_access_token")
def refresh_prt_to_access_token():
    prt_id = request.form.get("prt_id")
    if not prt_id:
        return create_response(400, "No prt_id specified.")
    client_id = request.form.get("client_id") or "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    resource = request.form.get("resource") or "https://graph.microsoft.com"
    refresh_prt = request.form.get("refresh_prt", "true").lower() == "true"
    redirect_uri = request.form.get("redirect_uri")
    access_token_id = prt.refresh_to_access_token(prt_id, client_id, resource, refresh_prt, redirect_uri)
    return create_response(200, f"Successfully refreshed PRT to access token {access_token_id}.", {"access_token_id": access_token_id})


@bp.get("/api/active_prt/<id>")
def set_active_prt(id):
    existing = connection.query_db("SELECT value FROM settings WHERE setting = 'active_prt_id'", one=True)
    if not existing:
        connection.execute_db("INSERT INTO settings (setting, value) VALUES ('active_prt_id', ?)", (id,))
    else:
        connection.execute_db("UPDATE settings SET value = ? WHERE setting = 'active_prt_id'", (id,))
    return id


@bp.get("/api/active_prt")
def get_active_prt():
    row = connection.query_db("SELECT value FROM settings WHERE setting = 'active_prt_id'", one=True)
    return f"{row[0]}" if row else "0"


@bp.post("/api/generate_prt_cookie")
def generate_prt_cookie():
    prt_id = request.form.get("prt_id")
    if not prt_id:
        return create_response(400, "No prt_id specified.")
    cookie = prt.generate_cookie(prt_id)
    return create_response(200, f"Generated PRT cookie using PRT {prt_id}.", {"prt_cookie": cookie})


@bp.post("/api/register_winhello")
def register_winhello():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return create_response(400, "No access_token_id specified.")
    winhello_id = winhello.register(access_token_id)
    return create_response(200, f"Registered WinHello with ID {winhello_id}.", {"winhello_id": winhello_id})


@bp.post("/api/import_winhello_key")
def import_winhello_key():
    import time
    private_key_pem_base64 = request.form.get("private_key_pem_base64")
    if not private_key_pem_base64:
        return create_response(400, "No private_key_pem_base64 specified.")
    device_id = request.form.get("device_id")
    if not device_id:
        return create_response(400, "No device_id specified.")
    user = request.form.get("user")
    if not user:
        return create_response(400, "No user specified.")
    key_id = request.form.get("key_id") or "Unknown"
    winhello_key_id = connection.execute_db(
        "INSERT INTO winhello_keys (stored_at, key_id, device_id, user, priv_key) VALUES (?, ?, ?, ?, ?)",
        (int(time.time()), key_id, device_id, user, private_key_pem_base64),
    )
    return create_response(200, f"Added WinHello key with ID {winhello_key_id}.", {"winhello_key_id": winhello_key_id})


@bp.get("/api/list_winhello_keys")
def list_winhello_keys():
    rows = connection.query_db_json("SELECT * FROM winhello_keys")
    return create_response(200, data=rows)


@bp.post("/api/winhello_to_prt")
def winhello_to_prt():
    winhello_id = request.form.get("winhello_id")
    if not winhello_id:
        return create_response(400, "No winhello_id specified.")
    device_id = request.form.get("device_id")
    if not device_id and request.form.get("device_db_id"):
        row = connection.query_db(
            "SELECT device_id FROM device_certificates WHERE id = ?",
            [request.form["device_db_id"]], one=True
        )
        device_id = row[0] if row else None
    winhello_username = request.form.get("winhello_username")
    prt_id = winhello.to_prt(winhello_id, device_id, winhello_username)
    return create_response(200, f"Obtained PRT with ID {prt_id} from WinHello key.", {"prt_id": prt_id})


@bp.post("/api/delete_winhello_key")
def delete_winhello_key():
    id = request.form.get("id")
    if not id:
        return create_response(400, "No id specified.")
    connection.execute_db("DELETE FROM winhello_keys WHERE id = ?", [id])
    return create_response(200, f"Deleted WinHello key with ID {id}.")