# graphspy/core/prt.py

# Built-in imports
import base64
import binascii
import json
import os
import time
from datetime import datetime

# External library imports
import jwt
import requests
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode
from cryptography.hazmat.backends import default_backend
from loguru import logger

# Local library imports
from ..db import connection
from ..core import user_agent as ua
from .errors import AppError
from .tokens import parse_token_endpoint_error, save_access_token, save_refresh_token


def get_srv_challenge_nonce() -> str:
    response = requests.post(
        "https://login.microsoftonline.com/common/oauth2/token",
        data={"grant_type": "srv_challenge"},
    )
    if response.status_code != 200:
        raise AppError(
            f"Failed to obtain nonce.\n{parse_token_endpoint_error(response)}"
        )
    nonce = response.json().get("Nonce")
    if not nonce:
        raise AppError("Failed to obtain nonce. No 'Nonce' in response.")
    return nonce


def decrypt_session_key(session_key_jwe: str, private_key) -> str:
    from cryptography.hazmat.primitives.asymmetric import padding as apadding

    jwe_payload_base64 = session_key_jwe.split(".")[1]
    jwe_payload_bytes = base64.urlsafe_b64decode(
        jwe_payload_base64 + "=" * (len(jwe_payload_base64) % 4)
    )
    session_key_bytes = private_key.decrypt(
        jwe_payload_bytes,
        apadding.OAEP(apadding.MGF1(hashes.SHA1()), hashes.SHA1(), None),
    )
    return binascii.hexlify(session_key_bytes).decode("utf-8")


def calculate_derived_key(session_key: bytes, context: bytes) -> bytes:
    kdf = KBKDFHMAC(
        algorithm=hashes.SHA256(),
        mode=Mode.CounterMode,
        length=32,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=b"AzureAD-SecureConversation",
        context=context,
        fixed=None,
        backend=default_backend(),
    )
    return kdf.derive(session_key)


def request_for_device(
    device_id: str, refresh_token_id: int, os_version: str = "10.0.26100"
) -> int:
    nonce = get_srv_challenge_nonce()
    refresh_token = connection.query_db(
        "SELECT refreshtoken FROM refreshtokens WHERE id = ?",
        [refresh_token_id],
        one=True,
    )[0]
    refresh_token_user = connection.query_db(
        "SELECT user FROM refreshtokens WHERE id = ?", [refresh_token_id], one=True
    )[0]
    if not refresh_token:
        raise AppError(f"No refresh token with ID {refresh_token_id}!")
    certificate_base64 = connection.query_db(
        "SELECT certificate FROM device_certificates WHERE device_id = ?",
        [device_id],
        one=True,
    )[0]
    private_key_base64 = connection.query_db(
        "SELECT priv_key FROM device_certificates WHERE device_id = ?",
        [device_id],
        one=True,
    )[0]
    if not certificate_base64 or not private_key_base64:
        raise AppError(f"No certificate or private key for device {device_id}!")
    private_key = serialization.load_pem_private_key(
        base64.b64decode(private_key_base64), password=None
    )
    jwt_payload = {
        "client_id": "29d9ed98-a469-4536-ade2-f981bc1d605e",
        "request_nonce": nonce,
        "scope": "openid aza ugs",
        "group_sids": [],
        "win_ver": os_version,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    request_jwt = jwt.encode(
        jwt_payload,
        key=private_key,
        algorithm="RS256",
        headers={"x5c": certificate_base64, "kdf_ver": 2},
    )
    response = requests.post(
        "https://login.microsoftonline.com/common/oauth2/token",
        data={
            "windows_api_version": "2.2",
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "request": request_jwt,
            "tgt": False,
        },
        headers={"User-Agent": ua.get()},
    )
    if response.status_code != 200:
        raise AppError(parse_token_endpoint_error(response))
    response_json = response.json()
    logger.debug("PRT request response:\n{}", response_json)
    if "refresh_token" not in response_json or "session_key_jwe" not in response_json:
        raise AppError(
            "Failed to request PRT. No 'refresh_token' or 'session_key_jwe' in response."
        )
    prt = response_json["refresh_token"]
    session_key_hex = decrypt_session_key(response_json["session_key_jwe"], private_key)
    return connection.execute_db(
        "INSERT INTO primary_refresh_tokens (device_id, user, prt, session_key, issued_at, expires_at, description) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            device_id,
            refresh_token_user,
            prt,
            session_key_hex,
            int(datetime.now().timestamp()),
            response_json["expires_on"],
            f"Created using refresh token {refresh_token_id}",
        ),
    )


def refresh_to_access_token(
    prt_id: int,
    client_id: str = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    resource: str = "https://graph.microsoft.com",
    refresh_prt: bool = True,
    redirect_uri: str = None,
) -> int:
    prt_row = connection.query_db_json(
        "SELECT * FROM primary_refresh_tokens WHERE id = ?", [prt_id], one=True
    )
    if not prt_row:
        raise AppError(f"No PRT found with ID {prt_id}!")
    prt = prt_row["prt"]
    session_key = binascii.unhexlify(prt_row["session_key"])
    nonce = get_srv_challenge_nonce()
    jwt_payload = {
        "win_ver": "10.0.26100",
        "scope": "openid aza" if refresh_prt else "openid",
        "request_nonce": nonce,
        "refresh_token": prt,
        "redirect_uri": redirect_uri
        or f"ms-appx-web://Microsoft.AAD.BrokerPlugin/{client_id}",
        "iss": "aad:brokerplugin",
        "grant_type": "refresh_token",
        "client_id": client_id,
        "resource": resource,
        "aud": "login.microsoftonline.com",
        "iat": str(int(time.time())),
        "exp": str(int(time.time()) + 3600),
    }
    context = os.urandom(24)
    jwt_headers = {"ctx": base64.b64encode(context).decode("utf-8"), "kdf_ver": 2}
    tempjwt = jwt.encode(
        jwt_payload, os.urandom(32), algorithm="HS256", headers=jwt_headers
    )
    jbody = tempjwt.split(".")[1]
    jwtbody = base64.urlsafe_b64decode(jbody + "=" * (len(jbody) % 4))
    digest = hashes.Hash(hashes.SHA256())
    digest.update(context)
    digest.update(jwtbody)
    kdfcontext = digest.finalize()
    derived_key = calculate_derived_key(session_key, kdfcontext)
    request_jwt = jwt.encode(
        jwt_payload, derived_key, algorithm="HS256", headers=jwt_headers
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
    headerdata, enckey, iv, ciphertext, authtag = response.text.split(".")
    logger.debug("PRT to access token response:\n{}", response.text)
    response_context = json.loads(
        base64.urlsafe_b64decode(headerdata + "=" * (len(headerdata) % 4))
    ).get("ctx")
    response_derived_key = calculate_derived_key(
        session_key, base64.b64decode(response_context)
    )
    iv_raw = base64.urlsafe_b64decode(iv + "=" * (len(iv) % 4))
    ciphertext_raw = base64.urlsafe_b64decode(ciphertext + "=" * (len(ciphertext) % 4))
    if len(iv_raw) == 12:
        aesgcm = AESGCM(response_derived_key)
        authtag_raw = base64.urlsafe_b64decode(authtag + "=" * (len(authtag) % 4))
        decrypted = aesgcm.decrypt(
            iv_raw, ciphertext_raw + authtag_raw, headerdata.encode("utf-8")
        )
    else:
        cipher = Cipher(algorithms.AES(response_derived_key), modes.CBC(iv_raw))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext_raw) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_data) + unpadder.finalize()
    decrypted_json = json.loads(decrypted)
    logger.debug("Decrypted PRT to access token response:\n{}", decrypted_json)
    if "access_token" not in decrypted_json:
        raise AppError(
            "Failed to request access token with PRT. No 'access_token' in decrypted response."
        )
    access_token_row_id = save_access_token(
        decrypted_json["access_token"], f"Created using PRT {prt_id}"
    )
    issued_at = int(datetime.now().timestamp())
    expires_at = issued_at + int(decrypted_json["refresh_token_expires_in"])
    if refresh_prt and "refresh_token" in decrypted_json:
        connection.execute_db(
            "INSERT INTO primary_refresh_tokens (device_id, user, prt, session_key, issued_at, expires_at, description) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                prt_row["device_id"],
                prt_row["user"],
                decrypted_json["refresh_token"],
                prt_row["session_key"],
                issued_at,
                expires_at,
                f"Refreshed from PRT {prt_id}",
            ),
        )
    elif "refresh_token" in decrypted_json:
        connection.execute_db(
            "INSERT INTO refreshtokens (stored_at, description, user, tenant_id, client_id, resource, foci, refreshtoken) VALUES (?,?,?,?,?,?,?,?)",
            (
                f"{datetime.now()}".split(".")[0],
                f"Created using PRT {prt_id}",
                prt_row["user"],
                "common",
                client_id,
                resource,
                decrypted_json.get("foci", 0),
                decrypted_json.get("refresh_token"),
            ),
        )
    return access_token_row_id


def generate_cookie(prt_id: int) -> str:
    prt_row = connection.query_db_json(
        "SELECT * FROM primary_refresh_tokens WHERE id = ?", [prt_id], one=True
    )
    if not prt_row:
        raise AppError(f"No PRT found with ID {prt_id}!")
    prt = prt_row["prt"]
    session_key = binascii.unhexlify(prt_row["session_key"])
    nonce = get_srv_challenge_nonce()
    context = os.urandom(24)
    jwt_headers = {"ctx": base64.b64encode(context).decode("utf-8"), "kdf_ver": 2}
    jwt_payload = {"refresh_token": prt, "is_primary": "true", "request_nonce": nonce}
    tempjwt = jwt.encode(
        jwt_payload, os.urandom(32), algorithm="HS256", headers=jwt_headers
    )
    jbody = tempjwt.split(".")[1]
    jwtbody = base64.urlsafe_b64decode(jbody + "=" * (len(jbody) % 4))
    digest = hashes.Hash(hashes.SHA256())
    digest.update(context)
    digest.update(jwtbody)
    kdfcontext = digest.finalize()
    derived_key = calculate_derived_key(session_key, kdfcontext)
    return jwt.encode(jwt_payload, derived_key, algorithm="HS256", headers=jwt_headers)
