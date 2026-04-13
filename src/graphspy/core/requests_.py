# graphspy/core/requests_.py

# Built-in imports
import json
import time

# External library imports
import requests
from loguru import logger

# Local library imports
from ..db import connection
from ..core import user_agent as ua


def graph_request(
    graph_uri: str, access_token_id: int, method: str = "GET", body: dict = {}
) -> str:
    row = connection.query_db(
        "SELECT accesstoken FROM accesstokens WHERE id = ?", [access_token_id], one=True
    )
    if not row:
        return json.dumps({"error": f"No access token with ID {access_token_id}"})
    headers = {
        "Authorization": f"Bearer {row[0]}",
        "User-Agent": ua.get(),
    }
    response = requests.request(
        method, graph_uri, headers=headers, **({"json": body} if body else {})
    )
    try:
        return json.dumps(response.json())
    except ValueError:
        return response.text or ""


def graph_upload_request(upload_uri: str, access_token_id: int, file) -> tuple:
    row = connection.query_db(
        "SELECT accesstoken FROM accesstokens WHERE id = ?", [access_token_id], one=True
    )
    if not row:
        return json.dumps({"error": "Invalid access token ID"}), 400
    headers = {
        "Authorization": f"Bearer {row[0]}",
        "Content-Type": file.content_type,
        "User-Agent": ua.get(),
    }
    response = requests.put(upload_uri, headers=headers, data=file.read())
    if response.status_code in [200, 201, 202]:
        return (
            json.dumps({"message": "File uploaded successfully."}),
            response.status_code,
        )
    return (
        json.dumps({"error": "Failed to upload file.", "details": response.text}),
        response.status_code,
    )


def make_request(
    uri: str,
    access_token_id: int,
    method: str,
    request_type: str,
    body,
    headers: dict | None = None,
    cookies: dict | None = None,
) -> dict:
    if headers is None:
        headers = {}
    if cookies is None:
        cookies = {}

    access_token = connection.query_db(
        "SELECT accesstoken FROM accesstokens WHERE id = ?", [access_token_id], one=True
    )
    if not access_token:
        return {
            "response_status_code": 400,
            "response_type": "text",
            "response_text": f"No access token with ID {access_token_id}",
            "response_headers": {},
        }
    headers["Authorization"] = f"Bearer {access_token[0]}"
    headers["User-Agent"] = ua.get()

    retry_count = 3
    while retry_count > 0:
        if not body:
            response = requests.request(method, uri, headers=headers, cookies=cookies)
        elif request_type in ["text", "urlencoded", "xml"]:
            if request_type == "urlencoded" and "Content-Type" not in headers:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            if request_type == "xml" and "Content-Type" not in headers:
                headers["Content-Type"] = "application/xml"
            response = requests.request(
                method, uri, headers=headers, data=body, cookies=cookies
            )
        elif request_type == "json":
            try:
                if isinstance(body, str):
                    body = json.loads(body)
                response = requests.request(
                    method, uri, headers=headers, json=body, cookies=cookies
                )
            except ValueError:
                return {
                    "response_status_code": 400,
                    "response_type": "text",
                    "response_text": "[Error] The body does not contain valid JSON.",
                    "response_headers": {},
                }
        else:
            return {
                "response_status_code": 400,
                "response_type": "text",
                "response_text": "[Error] Invalid request type.",
                "response_headers": {},
            }

        if response.status_code == 429 and "Retry-After" in response.headers:
            retry_count -= 1
            retry_delay = int(response.headers["Retry-After"]) + 1
            logger.debug(
                f"Request throttled. Received status code 429. Retrying after {retry_delay} seconds [{retry_count} attempts left]"
            )
            time.sleep(retry_delay)
        else:
            break

    content_type = response.headers.get("Content-Type", "")
    response_type = (
        "json" if "json" in content_type else "xml" if "xml" in content_type else "text"
    )
    try:
        response_text = (
            json.dumps(response.json()) if response_type == "json" else response.text
        )
    except ValueError:
        response_text = response.text

    return {
        "response_status_code": response.status_code,
        "response_type": response_type,
        "response_text": response_text,
        "response_headers": dict(response.headers),
    }
