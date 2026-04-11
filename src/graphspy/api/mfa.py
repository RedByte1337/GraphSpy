# graphspy/api/mfa.py

# Built-in imports
import json

# External library imports
from flask import Blueprint, request

# Local library imports
from ..core import mfa
from .helpers import create_response

bp = Blueprint("mfa", __name__)


@bp.post("/api/get_available_authentication_info")
def get_available_authentication_info():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    result = mfa.get_available_authentication_info(access_token_id)
    if not result:
        return "[Error] Failed to obtain Available Authentication Info.", 400
    return result


@bp.post("/api/add_phone_number")
def add_phone_number():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    country_code = request.form.get("country_code")
    if not country_code:
        return "[Error] No country_code specified.", 400
    phone_number = request.form.get("phone_number")
    if not phone_number:
        return "[Error] No phone_number specified.", 400
    phone_type = request.form.get("phone_type", "mobilePhone_sms")
    if phone_type not in [
        "mobilePhone_sms",
        "mobilePhone_call",
        "altMobilePhone",
        "officePhone",
    ]:
        return "[Error] Unknown phone_type specified.", 400
    result = mfa.add_phone_number(
        access_token_id, country_code, phone_number, phone_type
    )
    if not result:
        return "[Error] Failed to add phone number.", 400
    return result


@bp.post("/api/add_email")
def add_email():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    email = request.form.get("email")
    if not email:
        return "[Error] No email specified.", 400
    result = mfa.add_email(access_token_id, email)
    if not result:
        return "[Error] Failed adding email address.", 400
    return result


@bp.post("/api/add_mfa_app")
def add_mfa_app():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    security_info_type = request.form.get("security_info_type")
    if not security_info_type:
        return "[Error] No security_info_type specified.", 400
    secret_key = request.form.get("secret_key")
    if not secret_key:
        return "[Error] No secret_key specified.", 400
    affinity_region = request.form.get("affinity_region", None)
    result = mfa.add_mfa_app(access_token_id, security_info_type, secret_key, affinity_region)
    if not result:
        return "[Error] Failed to add MFA app.", 400
    return result


@bp.post("/api/list_graphspy_otp")
def list_graphspy_otp():
    from ..db import connection

    rows = connection.query_db_json("SELECT * FROM mfa_otp")
    return json.dumps(rows)


@bp.post("/api/add_graphspy_otp")
def add_graphspy_otp():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    description = request.form.get("description", "")
    result = mfa.add_graphspy_otp(access_token_id, description)
    if not result:
        return "[Error] Failed to add GraphSpy OTP code to account.", 400
    return f"[Success] Added GraphSpy OTP code with secret '{result}' to account!"


@bp.post("/api/delete_graphspy_otp")
def delete_graphspy_otp():
    import traceback
    from ..db import connection

    try:
        otp_code_id = request.form.get("otp_code_id")
        if not otp_code_id:
            return "[Error] No otp_code_id specified.", 400
        connection.execute_db("DELETE FROM mfa_otp WHERE id = ?", [otp_code_id])
        return f"[Success] OTP code with ID {otp_code_id} deleted from database."
    except Exception as e:
        traceback.print_exc()
        return "[Error] Failed to delete OTP code.", 400


@bp.post("/api/generate_otp_code")
def generate_otp_code():
    import traceback
    import pyotp

    try:
        secret_key = request.form.get("secret_key")
        if not secret_key:
            return "[Error] No secret_key specified.", 400
        return pyotp.TOTP(secret_key).now()
    except Exception as e:
        traceback.print_exc()
        return "[Error] Failed to create OTP code from the provided secret key.", 400


@bp.post("/api/add_security_key")
def add_security_key():
    import traceback

    try:
        access_token_id = request.form.get("access_token_id")
        if not access_token_id:
            return "[Error] No access_token_id specified.", 400
        client_type = request.form.get("client_type")
        if not client_type:
            return "[Error] No client_type specified.", 400
        description = request.form.get("description") or "GraphSpy Key"
        device_pin = request.form.get("device_pin", "")
        return mfa.add_security_key(
            access_token_id, description, client_type, device_pin
        )
    except Exception as e:
        traceback.print_exc()
        return create_response(
            400, "An unexpected error occurred when trying to add the security key."
        )


@bp.get("/api/get_security_key_status")
def get_security_key_status():
    from flask import current_app

    return current_app.config.get("add_security_key_status", "UNKNOWN")


@bp.post("/api/verify_security_info")
def verify_security_info():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    security_info_type = request.form.get("security_info_type")
    if not security_info_type:
        return "[Error] No security_info_type specified.", 400
    verification_context = request.form.get("verification_context")
    if not verification_context:
        return "[Error] No verification_context specified.", 400
    verification_data = request.form.get("verification_data", None)
    result = mfa.verify_security_info(
        access_token_id, security_info_type, verification_context, verification_data
    )
    if not result:
        return "[Error] Failed to verify security info.", 400
    return result


@bp.post("/api/delete_security_info")
def delete_security_info():
    if not request.is_json:
        return "[Error] Expecting JSON input.", 400
    data = request.get_json()
    access_token_id = data.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    security_info_type = data.get("security_info_type")
    if not security_info_type:
        return "[Error] No security_info_type specified.", 400
    payload = data.get("data")
    if not payload:
        return "[Error] No data specified.", 400
    result = mfa.delete_security_info(access_token_id, security_info_type, payload)
    if not result:
        return "[Error] Failed to delete MFA method.", 400
    return result


@bp.post("/api/validate_captcha")
def validate_captcha():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    challenge_id = request.form.get("challenge_id")
    if not challenge_id:
        return "[Error] No challenge_id specified.", 400
    captcha_solution = request.form.get("captcha_solution")
    if not captcha_solution:
        return "[Error] No captcha_solution specified.", 400
    azure_region = request.form.get("azure_region")
    if not azure_region:
        return "[Error] No azure_region specified.", 400
    challenge_type = request.form.get("challenge_type", "Visual")
    result = mfa.validate_captcha(
        access_token_id, challenge_id, captcha_solution, azure_region, challenge_type
    )
    if not result:
        return "[Error] Failed to validate captcha.", 400
    if not result["CaptchaSolved"]:
        return f"[Error] Captcha not solved. Received error: {result['ErrorCode']}", 400
    return result


@bp.post("/api/initialize_mobile_app_registration")
def initialize_mobile_app_registration():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    security_info_type = request.form.get("security_info_type")
    if not security_info_type:
        return "[Error] No security_info_type specified.", 400
    result = mfa.initialize_mobile_app_registration(access_token_id, security_info_type)
    if not result:
        return "[Error] Failed to initialize mobile app registration.", 400
    return result
