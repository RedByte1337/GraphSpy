# graphspy/core/winhello.py

# Built-in imports
import base64
import time
from datetime import datetime

# External library imports
import jwt
import requests
from cryptography.hazmat.primitives import hashes, serialization
from loguru import logger

# Local library imports
from ..db import connection
from ..core import user_agent as ua
from .device import generate_key_pair, generate_public_key_rsa_blob
from .errors import AppError
from .prt import decrypt_session_key, get_srv_challenge_nonce
from .tokens import parse_token_endpoint_error


def register(access_token_id: int) -> int:
    row = connection.query_db(
        "SELECT accesstoken FROM accesstokens WHERE id = ?", [access_token_id], one=True
    )
    if not row:
        raise AppError(f"No access token with ID {access_token_id}!")
    access_token = row[0]
    decoded = jwt.decode(access_token, options={"verify_signature": False})
    device_id = decoded.get("deviceid", "00000000-0000-0000-0000-000000000000")
    if "deviceid" not in decoded:
        logger.error(
            f"No device ID found in access token with ID {access_token_id}! This will probably fail!"
        )
    private_key, private_key_bytes, public_key = generate_key_pair()
    private_key_base64 = base64.b64encode(private_key_bytes).decode("utf-8")
    pubkeycngblob = generate_public_key_rsa_blob(public_key)
    response = requests.post(
        "https://enterpriseregistration.windows.net/EnrollmentServer/key/?api-version=1.0",
        headers={
            "Authorization": f"Bearer {access_token}",
            "User-Agent": "Dsreg/10.0 (Windows 10.0.19044.1826)",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        json={"kngc": pubkeycngblob.decode("utf-8")},
    )
    if response.status_code != 200:
        raise AppError(
            f"Failed to register WinHello. Received status code {response.status_code}"
        )
    response_json = response.json()
    key_id = response_json.get("kid", "00000000-0000-0000-0000-000000000000")
    user = response_json.get("upn", "Unknown")
    return connection.execute_db(
        "INSERT INTO winhello_keys (stored_at, key_id, device_id, user, priv_key) VALUES (?, ?, ?, ?, ?)",
        (int(time.time()), key_id, device_id, user, private_key_base64),
    )


def to_prt(
    winhello_id: int, device_id: str = None, winhello_username: str = None
) -> int:
    row = connection.query_db(
        "SELECT * FROM winhello_keys WHERE id = ?", [winhello_id], one=True
    )
    if not row:
        raise AppError(f"No WinHello key with ID {winhello_id}!")
    winhello_private_key = serialization.load_pem_private_key(
        base64.b64decode(row["priv_key"]), password=None
    )
    winhello_public_key = winhello_private_key.public_key()
    pubkeycngblob = base64.b64decode(generate_public_key_rsa_blob(winhello_public_key))
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pubkeycngblob)
    kid = base64.b64encode(digest.finalize()).decode("utf-8")
    device_id = device_id or row["device_id"]
    winhello_username = winhello_username or row["user"]
    winhello_assertion = jwt.encode(
        {
            "iss": winhello_username,
            "aud": "common",
            "iat": int(time.time()) - 3600,
            "exp": int(time.time()) + 3600,
            "request_nonce": get_srv_challenge_nonce(),
            "scope": "openid aza ugs",
        },
        base64.b64decode(row["priv_key"]),
        algorithm="RS256",
        headers={"kid": kid, "use": "ngc"},
    )
    device_cert_row = connection.query_db(
        "SELECT certificate, priv_key FROM device_certificates WHERE device_id = ?",
        [device_id],
        one=True,
    )
    if not device_cert_row:
        raise AppError(f"No certificate or private key for device {device_id}!")
    device_private_key = serialization.load_pem_private_key(
        base64.b64decode(device_cert_row["priv_key"]), password=None
    )
    request_jwt = jwt.encode(
        {
            "client_id": "38aa3b87-a06d-4817-b275-7a316988d93b",
            "request_nonce": get_srv_challenge_nonce(),
            "scope": "openid aza ugs",
            "group_sids": [],
            "win_ver": "10.0.19041.868",
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "username": winhello_username,
            "assertion": winhello_assertion,
        },
        device_private_key,
        algorithm="RS256",
        headers={"x5c": device_cert_row["certificate"], "kdf_ver": 2},
    )
    response = requests.post(
        "https://login.microsoftonline.com/common/oauth2/token",
        data={
            "windows_api_version": "2.2",
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "request": request_jwt,
            "client_info": "1",
        },
        headers={"User-Agent": ua.get()},
    )
    if response.status_code != 200:
        raise AppError(parse_token_endpoint_error(response))
    response_json = response.json()
    logger.debug(f"PRT request response:\n{response_json}")
    if "refresh_token" not in response_json or "session_key_jwe" not in response_json:
        raise AppError(
            "Failed to request PRT. No 'refresh_token' or 'session_key_jwe' in response."
        )
    session_key_hex = decrypt_session_key(
        response_json["session_key_jwe"], device_private_key
    )
    return connection.execute_db(
        "INSERT INTO primary_refresh_tokens (device_id, user, prt, session_key, issued_at, expires_at, description) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            device_id,
            winhello_username,
            response_json["refresh_token"],
            session_key_hex,
            int(datetime.now().timestamp()),
            response_json["expires_on"],
            f"Created with WinHello key {winhello_id}",
        ),
    )
