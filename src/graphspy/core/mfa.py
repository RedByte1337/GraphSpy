# graphspy/core/mfa.py

# Built-in imports
import json
import traceback
import uuid
from datetime import datetime

# External library imports
import pyotp
import requests

# Local library imports
from ..db import connection
from ..core import user_agent as ua


def get_session_ctx(access_token_id: int):
    row = connection.query_db(
        "SELECT accesstoken FROM accesstokens WHERE id = ? AND resource LIKE '%19db86c3-b2b9-44cc-b339-36da233a3be2%'",
        [access_token_id],
        one=True,
    )
    if not row:
        return False
    try:
        response = requests.post(
            "https://mysignins.microsoft.com/api/session/authorize",
            headers={"Authorization": f"Bearer {row[0]}", "User-Agent": ua.get()},
            json={},
        )
        if response.status_code != 200:
            return False
        return response.json()["sessionCtxV2"]
    except Exception:
        traceback.print_exc()
        return False


def _get_access_token_for_mfa(access_token_id: int):
    row = connection.query_db(
        "SELECT accesstoken FROM accesstokens WHERE id = ? AND resource LIKE '%19db86c3-b2b9-44cc-b339-36da233a3be2%'",
        [access_token_id],
        one=True,
    )
    return row[0] if row else None


def _mfa_headers(access_token_id: int) -> dict | None:
    access_token = _get_access_token_for_mfa(access_token_id)
    if not access_token:
        return None
    session_ctx = get_session_ctx(access_token_id)
    if not session_ctx:
        return None
    return {
        "Authorization": f"Bearer {access_token}",
        "Sessionctxv2": session_ctx,
        "User-Agent": ua.get(),
    }


def get_available_authentication_info(access_token_id: int):
    headers = _mfa_headers(access_token_id)
    if not headers:
        return False
    try:
        response = requests.get(
            "https://mysignins.microsoft.com/api/authenticationmethods/availablemethods",
            headers=headers,
        )
        if response.status_code != 200:
            return False
        info = response.json()
        return [{**info[m], "MethodName": m} for m in info.keys()]
    except Exception:
        traceback.print_exc()
        return False


def validate_captcha(
    access_token_id: int,
    challenge_id: str,
    captcha_solution: str,
    azure_region: str,
    challenge_type: str = "Visual",
):
    headers = _mfa_headers(access_token_id)
    if not headers:
        return False
    try:
        response = requests.post(
            "https://mysignins.microsoft.com/api/captcha/validation",
            headers=headers,
            json={
                "ChallengeType": challenge_type,
                "ChallengeId": challenge_id,
                "InputSolution": captcha_solution,
                "AzureRegion": azure_region,
            },
        )
        return response.json() if response.status_code == 200 else False
    except Exception:
        traceback.print_exc()
        return False


def initialize_mobile_app_registration(access_token_id: int, security_info_type):
    headers = _mfa_headers(access_token_id)
    if not headers:
        return False
    try:
        response = requests.post(
            "https://mysignins.microsoft.com/api/authenticationmethods/initializemobileapp",
            headers=headers,
            json={"securityInfoType": security_info_type},
        )
        return response.json() if response.status_code == 200 else False
    except Exception:
        traceback.print_exc()
        return False


def add_security_info(access_token_id: int, security_info_type, data=None):
    headers = _mfa_headers(access_token_id)
    if not headers:
        return False
    headers["X-Ms-Client-Session-Id"] = str(uuid.uuid4())
    try:
        body = {"Type": security_info_type}
        body_data = json.dumps(data) if isinstance(data, dict) else data
        if body_data:
            body["Data"] = body_data
        response = requests.post(
            "https://mysignins.microsoft.com/api/authenticationmethods/new",
            headers=headers,
            json=body,
        )
        if response.status_code != 200:
            return False
        security_info_response = response.json()
        if (
            not security_info_response
            or "VerificationContext" not in security_info_response
        ):
            return False
        if (
            not security_info_response["VerificationContext"]
            and security_info_response.get("ErrorCode") == 28
        ):
            captcha_response = requests.get(
                "https://mysignins.microsoft.com/api/captcha/?challengeType=Visual&locale=en-US",
                headers=headers,
            )
            security_info_response["captcha"] = captcha_response.json()
        return security_info_response
    except Exception:
        traceback.print_exc()
        return False


def verify_security_info(
    access_token_id: int, security_info_type, verification_context, verification_data
):
    headers = _mfa_headers(access_token_id)
    if not headers:
        return False
    try:
        response = requests.post(
            "https://mysignins.microsoft.com/api/authenticationmethods/verify",
            headers=headers,
            json={
                "Type": security_info_type,
                "VerificationData": verification_data,
                "VerificationContext": verification_context,
            },
        )
        return response.json() if response.status_code == 200 else False
    except Exception:
        traceback.print_exc()
        return False


def delete_security_info(access_token_id: int, security_info_type, data):
    headers = _mfa_headers(access_token_id)
    if not headers:
        return False
    headers["X-Ms-Client-Session-Id"] = str(uuid.uuid4())
    try:
        body_data = json.dumps(data) if isinstance(data, dict) else data
        response = requests.post(
            "https://mysignins.microsoft.com/api/authenticationmethods/delete",
            headers=headers,
            json={"Type": security_info_type, "Data": body_data},
        )
        if response.status_code != 200:
            return False
        result = response.json()
        if not result or not result.get("Deleted"):
            return False
        return result
    except Exception:
        traceback.print_exc()
        return False


def add_phone_number(
    access_token_id: int,
    country_code: str,
    phone_number: str,
    phone_type: str = "mobilePhone_sms",
):
    phone_type_dict = {
        "mobilePhone_call": 5,
        "mobilePhone_sms": 6,
        "officePhone": 7,
        "altMobilePhone": 11,
    }
    if phone_type not in phone_type_dict:
        return False
    return add_security_info(
        access_token_id,
        phone_type_dict[phone_type],
        {"phoneNumber": phone_number, "countryCode": country_code},
    )


def add_email(access_token_id: int, email: str):
    return add_security_info(access_token_id, 8, email)


def add_mfa_app(access_token_id: int, security_info_type, secret_key: str):
    return add_security_info(
        access_token_id,
        security_info_type,
        {
            "secretKey": secret_key,
            "affinityRegion": None,
            "isResendNotificationChallenge": False,
        },
    )


def add_graphspy_otp(access_token_id: int, description: str = "") -> str | None:
    try:
        init_response = initialize_mobile_app_registration(access_token_id, 3)
        if not init_response:
            return False
        secret_key = init_response["SecretKey"]
        account_name = init_response.get("AccountName", "Unknown")
        security_info_response = add_security_info(
            access_token_id,
            3,
            {
                "secretKey": secret_key,
                "affinityRegion": None,
                "isResendNotificationChallenge": False,
            },
        )
        if not security_info_response or "captcha" in security_info_response:
            return False
        if not security_info_response.get("VerificationContext"):
            return False
        otp_code = pyotp.TOTP(secret_key).now()
        verify_response = verify_security_info(
            access_token_id, 3, security_info_response["VerificationContext"], otp_code
        )
        if verify_response.get("ErrorCode"):
            return False
        connection.execute_db(
            "INSERT INTO mfa_otp (stored_at, secret_key, account_name, description) VALUES (?,?,?,?)",
            (f"{datetime.now()}".split(".")[0], secret_key, account_name, description),
        )
        return secret_key
    except Exception:
        traceback.print_exc()
        return False


def add_security_key(
    access_token_id: int,
    key_description: str = "GraphSpy Key",
    client_type: str = "Windows",
    device_pin: str = None,
):
    from flask import current_app
    from fido2.hid import CtapHidDevice
    from fido2.client import Fido2Client, WindowsClient, UserInteraction
    from ..api.helpers import create_response

    current_app.config["add_security_key_status"] = "INIT"
    access_token = _get_access_token_for_mfa(access_token_id)
    if not access_token:
        return create_response(
            400, f"No access token with ID {access_token_id} and required resource."
        )

    security_info_response = add_security_info(access_token_id, 12)
    if not security_info_response or security_info_response.get("ErrorCode", 0) != 0:
        return create_response(
            400, "Something went wrong trying to add the security key."
        )

    security_info_data = json.loads(security_info_response["Data"])
    public_key_options = {
        "challenge": security_info_data["requestData"]["serverChallenge"].encode(
            "utf-8"
        ),
        "rp": {"name": "Microsoft", "id": "login.microsoft.com"},
        "user": {
            "id": __import__("base64").urlsafe_b64decode(
                security_info_data["requestData"]["userId"] + "=="
            ),
            "name": security_info_data["requestData"]["memberName"],
            "displayName": security_info_data["requestData"]["userDisplayName"],
            "icon": "",
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257},
        ],
        "timeout": 600000,
        "excludeCredentials": [],
        "authenticatorSelection": {
            "authenticatorAttachment": security_info_data["requestData"][
                "authenticator"
            ],
            "requireResidentKey": True,
            "userVerification": "required",
        },
        "attestation": "direct",
        "extensions": {"hmacCreateSecret": True},
    }
    current_app.config["add_security_key_status"] = "CLIENT_SETUP"
    if client_type == "Windows":
        if not WindowsClient.is_available():
            return create_response(400, "WindowsClient is not available!")
        client = WindowsClient("https://login.microsoft.com")
    else:
        dev = next(CtapHidDevice.list_devices(), None)
        if dev is None:
            try:
                from fido2.pcsc import CtapPcscDevice

                dev = next(CtapPcscDevice.list_devices(), None)
            except Exception:
                traceback.print_exc()
        if not dev:
            return create_response(400, "No valid FIDO authenticator device found.")

        class CliInteraction(UserInteraction):
            def prompt_up(self):
                current_app.config["add_security_key_status"] = "TOUCH"

            def request_pin(self, permissions, rd_id):
                current_app.config["add_security_key_status"] = "PIN"
                return device_pin

            def request_uv(self, permissions, rd_id):
                return True

        client = Fido2Client(
            dev, "https://login.microsoft.com", user_interaction=CliInteraction()
        )

    current_app.config["add_security_key_status"] = "CREDENTIAL_REGISTRATION"
    credential = client.make_credential(public_key_options)
    if not credential:
        return create_response(400, "Credential registration failed.")

    current_app.config["add_security_key_status"] = "VERIFY_DATA"
    import base64
    import uuid as _uuid

    client_data_json = json.loads(credential.client_data)
    verification_data = {
        "Name": key_description,
        "Canary": security_info_data["requestData"]["canary"],
        "AttestationObject": base64.urlsafe_b64encode(
            credential.attestation_object
        ).decode(),
        "ClientDataJson": base64.urlsafe_b64encode(
            json.dumps(client_data_json, separators=(",", ":")).encode()
        ).decode(),
        "CredentialId": base64.urlsafe_b64encode(
            credential.attestation_object.auth_data.credential_data.credential_id
        ).decode(),
        "ClientExtensionResults": base64.urlsafe_b64encode(
            str(credential.extension_results).encode()
        ).decode(),
        "PostInfo": "",
        "AAGuid": str(_uuid.uuid4()),
        "CredentialDeviceType": "singleDevice",
    }
    response = verify_security_info(
        access_token_id, 12, None, json.dumps(verification_data, separators=(",", ":"))
    )
    if response["ErrorCode"] != 0:
        return create_response(400, f"Failed to add security key.")
    current_app.config["add_security_key_status"] = "SUCCESS"
    return create_response(
        200, f"Successfully added new security key '{key_description}'."
    )
