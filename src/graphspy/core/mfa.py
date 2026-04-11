# graphspy/core/mfa.py

# Built-in imports
import base64
import json
import traceback
import uuid
from datetime import datetime

# External library imports
from flask import current_app
import requests
import pyotp
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, DefaultClientDataCollector, UserInteraction

# Local library imports
from ..api.helpers import create_response
from ..db import connection
from ..core import user_agent as ua


def _get_security_info_type(type_id):
    security_info_types_dict = {
        -1: "done",
        0: "unknown",
        1: "appNotificationAndCode",
        2: "appNotificationOnly",
        3: "appCodeOnly",
        4: "mobilePhoneCallAndSMS",
        5: "mobilePhoneCall",
        6: "mobilePhoneSMS",
        7: "officePhone",
        8: "email",
        9: "securityQuestions",
        10: "appPassword",
        11: "altMobilePhoneCall",
        12: "fido",
        13: "phoneSignIn",
        14: "temporaryAccessPass",
        15: "hardwareOath",
        16: "password",
        18: "passkey",
        19: "passkeyFromAuthenticator",
        100: "unsupportedAuthMethods"
    }
    return security_info_types_dict[type_id] if type_id in security_info_types_dict else security_info_types_dict[0]

def _get_verification_state(verification_state_id):
    verification_state_dict = {
        0: "unknown",
        1: "verificationPending",
        2: "verified",
        3: "verificationFailed",
        4: "systemError",
        5: "activationPending",
        6: "activationFailure",
        7: "activationSucceeded",
        8: "challengeExpired",
        9: "activationThrottled",
        10: "captchaRequired"
    }
    return verification_state_dict[verification_state_id] if verification_state_id in verification_state_dict else verification_state_dict[0]

def _get_security_info_error(error_id):
    add_security_info_error_dict = {
        0: "none",
        1: "userIsBlockedBySAS",
        2: "systemError",
        3: "invalidCanary",
        4: "badRequest",
        5: "dataNotFound",
        6: "ngcMfaRequired", # Access token requires the "ngcmfa" value in the "amr" claim
        7: "keyDisallowedByPolicy",
        8: "challengeExpired",
        9: "authorizationRequestDenied",
        10: "authTokenNotForTargetTenant",
        11: "authTokenNotFound",
        12: "invalidAikChain",
        13: "invalidAttestationDataFormat",
        14: "requiredParamMissing",
        15: "retryWebAuthN",
        16: "userNotFound",
        17: "badDirectoryRequest",
        18: "replicaUnavailable",
        19: "requestThrottled",
        20: "userGroupRestriction",
        21: "featureDisallowedByPolicy",
        22: "invalidKeyDataFormat",
        23: "attestationValidationFailed",
        24: "verificationFailed",
        25: "appSessionTimedOut",
        26: "activationThrottled",
        27: "appRequestTimedOut",
        28: "captchaRequired", # Trigger captcha. Usually after multiple failed SMS codes
        29: "badPhoneNumber",
        30: "deviceNotFound",
        31: "phoneAppNotificationDenied",
        32: "KeyNotFound",
        33: "InvalidSession",
        34: "OtherDefaultAvailable",
        35: "HardwareTokenAssigned"
    }
    return add_security_info_error_dict[error_id] if error_id in add_security_info_error_dict else add_security_info_error_dict[0]

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
            # ErrorCode 28 indicates that a Captcha needs to be solved (happens after a couple of failed attempts in a short timeframe)
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
    # Types:
    #   2 - Microsoft Authenticator App
    #   3 - OTP
    #   6 - MobilePhone
    #   7 - OfficePhone
    #   8 - Email
    #   11 - AltMobilePhone
    #   12 - FIDO
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


def add_mfa_app(access_token_id: int, security_info_type, secret_key: str, affinity_region: str = None):
    return add_security_info(
        access_token_id,
        security_info_type,
        {
            "secretKey": secret_key,
            "affinityRegion": affinity_region,
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

    current_app.config["add_security_key_status"] = "INIT"
    access_token = _get_access_token_for_mfa(access_token_id)
    if not access_token:
        return create_response(
            400, f"No access token with ID {access_token_id} and resource containing '19db86c3-b2b9-44cc-b339-36da233a3be2'!"
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
            "authenticatorAttachment": security_info_data["requestData"]["authenticator"],
            "requireResidentKey": True,
            "userVerification": "required",
        },
        "attestation": "direct",
        "extensions": {"hmacCreateSecret": True},
    }
    current_app.config["add_security_key_status"] = "CLIENT_SETUP"
    if client_type == "Windows":
        try:
            from fido2.client.windows import WindowsClient # Only importable on Windows!
            if not WindowsClient.is_available():
                return create_response(400, "Windows client requested, but WindowsClient is not available! Are you sure the GraphSpy server is running on a compatible Windows device?")
            client = WindowsClient(client_data_collector=DefaultClientDataCollector("https://login.microsoft.com"))
        except Exception:
            traceback.print_exc()
            return create_response(400, "Windows client requested, but WindowsClient is not available! Are you sure the GraphSpy server is running on a compatible Windows device?")
    else:
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            return create_response(400, "No valid FIDO authenticator device found. Admin/root privileges might be required to discover your Authenticator device when not using the Windows WebAuthn API.")

        class CliInteraction(UserInteraction):
            def prompt_up(self):
                current_app.config["add_security_key_status"] = "TOUCH"

            def request_pin(self, permissions, rd_id):
                current_app.config["add_security_key_status"] = "PIN"
                return device_pin

            def request_uv(self, permissions, rd_id):
                return True

        client = Fido2Client(
            dev, client_data_collector=DefaultClientDataCollector("https://login.microsoft.com"), user_interaction=CliInteraction()
        )

    current_app.config["add_security_key_status"] = "CREDENTIAL_REGISTRATION"
    credential = client.make_credential(public_key_options)
    if not credential or not "response" in credential:
        return create_response(400, "Credential registration failed.")

    credential_response = credential.response
    current_app.config["add_security_key_status"] = "VERIFY_DATA"

    client_data_json = json.loads(credential_response.client_data)
    verification_data = {
        "Name": key_description,
        "Canary": security_info_data["requestData"]["canary"],
        "AttestationObject": base64.urlsafe_b64encode(
            credential_response.attestation_object
        ).decode(),
        "ClientDataJson": base64.urlsafe_b64encode(
            json.dumps(client_data_json, separators=(",", ":")).encode("utf-8")
        ).decode(),
        "CredentialId": base64.urlsafe_b64encode(
            credential_response.attestation_object.auth_data.credential_data.credential_id
        ).decode(),
        "ClientExtensionResults": base64.urlsafe_b64encode(
            str(credential.client_extension_results).encode("utf-8")
        ).decode(),
        "PostInfo": "",
        "AAGuid": str(uuid.uuid4()),
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
