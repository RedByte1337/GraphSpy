# graphspy/core/tokens.py

# Built-in imports
import uuid
from datetime import datetime

# External library imports
import jwt
import requests

# Local library imports
from ..db import connection
from ..core import user_agent as ua


def parse_token_endpoint_error(response) -> str:
    try:
        error_code = response.json().get("error", "Unknown error")
        error_description = response.json().get("error_description", "Unknown error")
        return f"[{response.status_code}] {error_code}: {error_description}"
    except ValueError:
        return f"[{response.status_code}] {response.text}"


def is_valid_uuid(val) -> bool:
    try:
        uuid.UUID(str(val))
        return True
    except ValueError:
        return False


def get_tenant_id(tenant_domain: str) -> str:
    headers = {"User-Agent": ua.get()}
    response = requests.get(
        f"https://login.microsoftonline.com/{tenant_domain}/.well-known/openid-configuration",
        headers=headers,
    )
    return response.json()["authorization_endpoint"].split("/")[3]


def save_access_token(accesstoken: str, description: str) -> int:
    decoded = jwt.decode(accesstoken, options={"verify_signature": False})
    idtyp = decoded.get("idtyp")
    if idtyp == "user":
        user = decoded.get("unique_name") or decoded.get("upn") or "unknown"
    elif idtyp == "app":
        user = decoded.get("app_displayname") or decoded.get("appid") or "unknown"
    else:
        user = (
            decoded.get("unique_name")
            or decoded.get("upn")
            or decoded.get("app_displayname")
            or decoded.get("oid")
            or "unknown"
        )
    return connection.execute_db(
        "INSERT INTO accesstokens (stored_at, issued_at, expires_at, description, user, resource, accesstoken) VALUES (?,?,?,?,?,?,?)",
        (
            f"{datetime.now()}".split(".")[0],
            datetime.fromtimestamp(decoded["iat"]) if "iat" in decoded else "unknown",
            datetime.fromtimestamp(decoded["exp"]) if "exp" in decoded else "unknown",
            description,
            user,
            decoded.get("aud", "unknown"),
            accesstoken,
        ),
    )


def save_refresh_token(
    refreshtoken: str,
    description: str,
    user: str,
    tenant: str,
    resource: str,
    foci: int,
    client_id: str = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
) -> int:
    foci_int = 1 if foci else 0
    if tenant == "common":
        tenant_id = "common"
    else:
        tenant_id = (
            tenant.strip("\"{}-[]\\/' ")
            if is_valid_uuid(tenant.strip("\"{}-[]\\/' "))
            else get_tenant_id(tenant)
        )
    return connection.execute_db(
        "INSERT INTO refreshtokens (stored_at, description, user, tenant_id, client_id, resource, foci, refreshtoken) VALUES (?,?,?,?,?,?,?,?)",
        (
            f"{datetime.now()}".split(".")[0],
            description,
            user,
            tenant_id,
            client_id,
            resource,
            foci_int,
            refreshtoken,
        ),
    )


def refresh_to_access_token(
    refresh_token_id: int,
    client_id: str = "defined_in_token",
    resource: str = "defined_in_token",
    scope: str = "",
    store_refresh_token: bool = True,
    api_version: int = 1,
) -> int:
    refresh_token = connection.query_db(
        "SELECT refreshtoken FROM refreshtokens WHERE id = ?",
        [refresh_token_id],
        one=True,
    )[0]
    tenant_id = (
        connection.query_db(
            "SELECT tenant_id FROM refreshtokens WHERE id = ?",
            [refresh_token_id],
            one=True,
        )[0]
        or "common"
    )
    if resource == "defined_in_token":
        resource = connection.query_db(
            "SELECT resource FROM refreshtokens WHERE id = ?",
            [refresh_token_id],
            one=True,
        )[0]
    if client_id == "defined_in_token":
        client_id = connection.query_db(
            "SELECT client_id FROM refreshtokens WHERE id = ?",
            [refresh_token_id],
            one=True,
        )[0]

    body = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    url = f"https://login.microsoftonline.com/{tenant_id}"
    if api_version == 1:
        body["resource"] = resource
        url += "/oauth2/token?api-version=1.0"
    elif api_version == 2:
        body["scope"] = scope
        url += "/oauth2/v2.0/token"

    response = requests.post(url, data=body, headers={"User-Agent": ua.get()})
    if response.status_code != 200:
        return {parse_token_endpoint_error(response)}

    access_token = response.json()["access_token"]
    save_access_token(access_token, f"Created using refresh token {refresh_token_id}")
    access_token_id = connection.query_db(
        "SELECT id FROM accesstokens WHERE accesstoken = ?", [access_token], one=True
    )[0]

    if store_refresh_token:
        decoded = jwt.decode(access_token, options={"verify_signature": False})
        idtyp = decoded.get("idtyp")
        if idtyp == "user":
            user = decoded.get("unique_name") or decoded.get("upn") or "unknown"
        elif idtyp == "app":
            user = decoded.get("app_displayname") or decoded.get("appid") or "unknown"
        else:
            user = "unknown"
        save_refresh_token(
            response.json()["refresh_token"],
            f"Created using refresh token {refresh_token_id}",
            user,
            tenant_id,
            response.json().get("resource", "unknown"),
            response.json().get("foci", 0),
            client_id,
        )
    return access_token_id
