# graphspy/core/teams.py

# Built-in imports
import json
import re

# External library imports
import jwt
import requests
from flask import Response
from loguru import logger

# Local library imports
from ..core import user_agent as ua
from ..core.requests_ import make_request
from ..db import connection


def get_settings(access_token_id: int):
    cached = connection.query_db_json(
        "SELECT * FROM teams_settings WHERE access_token_id = ?",
        [access_token_id],
        one=True,
    )
    if (
        cached
        and int(__import__("datetime").datetime.now().timestamp())
        < cached["expires_at"]
    ):
        logger.debug("Found teams settings in database. Using those.")
        return cached
    row = connection.query_db(
        "SELECT accesstoken FROM accesstokens WHERE id = ? AND resource LIKE '%api.spaces.skype.com%'",
        [access_token_id],
        one=True,
    )
    if not row:
        logger.error("No access token with ID {} and resource containing 'api.spaces.skype.com'!", access_token_id)
        return False
    logger.debug("No teams settings found in database for access token with ID {}. Requesting new teams settings.", access_token_id)
    access_token = row[0]
    response = requests.post(
        "https://teams.microsoft.com/api/authsvc/v1.0/authz",
        headers={"Authorization": f"Bearer {access_token}", "User-Agent": ua.get()},
    )
    if response.status_code != 200:
        logger.error("Failed obtaining teams settings. Received status code {}", response.status_code)
        return False
    try:
        teams_json = response.json()
        skype_token = teams_json["tokens"]["skypeToken"]
        decoded = jwt.decode(skype_token, options={"verify_signature": False})
        connection.execute_db(
            "INSERT OR REPLACE INTO teams_settings (access_token_id, skypeToken, skype_id, issued_at, expires_at, teams_settings_raw) VALUES (?,?,?,?,?,?)",
            (
                access_token_id,
                skype_token,
                decoded["skypeid"],
                decoded["iat"],
                decoded["exp"],
                json.dumps(teams_json),
            ),
        )
        return connection.query_db_json(
            "SELECT * FROM teams_settings WHERE access_token_id = ?",
            [access_token_id],
            one=True,
        )
    except Exception:
        logger.error("Failed extracting teams settings from response.")
        return False


def get_conversations(access_token_id: int):
    settings = get_settings(access_token_id)
    if not settings:
        return "[Error] Unable to obtain teams settings.", 400
    chat_service_uri = json.loads(settings["teams_settings_raw"])["regionGtms"][
        "chatService"
    ]
    uri = f"{chat_service_uri}/v1/users/ME/conversations?view=msnp24Equivalent&pageSize=500"
    response = make_request(
        uri,
        access_token_id,
        "GET",
        "text",
        "",
        {"Authentication": f"skypetoken={settings['skypeToken']}"},
    )
    if response["response_status_code"] == 200 and response["response_type"] == "json":
        return json.loads(response["response_text"])
    return "[Error] Failed to obtain Teams conversations.", 400


def get_conversation_messages(access_token_id: int, conversation_link: str):
    settings = get_settings(access_token_id)
    if not settings:
        return "[Error] Unable to obtain teams settings.", 400
    uri = f"{conversation_link}?startTime=0&view=msnp24Equivalent&pageSize=200"
    response = make_request(
        uri,
        access_token_id,
        "GET",
        "text",
        "",
        {"Authentication": f"skypetoken={settings['skypeToken']}"},
    )
    if response["response_status_code"] == 200 and response["response_type"] == "json":
        data = json.loads(response["response_text"])
        data["messages"] = [
            {**msg, "isFromMe": msg["from"].endswith(settings["skype_id"])}
            for msg in data["messages"]
        ]
        return data
    return "[Error] Failed to obtain Teams conversation messages.", 400


def send_message(access_token_id: int, conversation_link: str, message_content: str):
    settings = get_settings(access_token_id)
    if not settings:
        return "[Error] Unable to obtain teams settings.", 400
    response = requests.post(
        conversation_link,
        headers={
            "Authentication": f"skypetoken={settings['skypeToken']}",
            "User-Agent": ua.get(),
        },
        json={"messagetype": "RichText/Html", "content": message_content},
    )
    if response.status_code >= 200 and response.status_code < 300:
        return f"{response.json().get('OriginalArrivalTime', 'Unknown')}"
    logger.error("Failed sending teams message. Received response status {}. Response body:\n{}", response.status_code, response.content)
    return f"[Error] Failed to send Teams message. Status {response.status_code}", 400


def get_conversation_members(access_token_id: int, conversation_id: str):
    settings = get_settings(access_token_id)
    if not settings:
        return "[Error] Unable to obtain teams settings.", 400
    service_uri = json.loads(settings["teams_settings_raw"])["regionGtms"][
        "teamsAndChannelsService"
    ]
    response = make_request(
        f"{service_uri}/beta/teams/{conversation_id}/members",
        access_token_id,
        "GET",
        "text",
        "",
        {},
    )
    if response["response_status_code"] == 200 and response["response_type"] == "json":
        members = json.loads(response["response_text"])
        logger.debug("Found {} members in conversation '{}'", len(members), conversation_id)
        return [
            {**m, "isCurrentUser": m["mri"].endswith(settings["skype_id"])}
            for m in members
        ]
    return "[Error] Failed to obtain Teams members.", 400


def get_image(access_token_id: int, image_uri: str):
    settings = get_settings(access_token_id)
    if not settings:
        return "[Error] Unable to obtain teams settings.", 400
    response = requests.get(
        image_uri,
        cookies={"skypetoken_asm": settings["skypeToken"]},
        headers={"User-Agent": ua.get()},
    )
    if response.status_code == 200:
        return Response(response.content, mimetype=response.headers["Content-Type"])
    return "[Error] Failed to obtain teams image.", 400


def list_users(access_token_id: int):
    settings = get_settings(access_token_id)
    if not settings:
        return "[Error] Unable to obtain teams settings.", 400
    service_uri = json.loads(settings["teams_settings_raw"])["regionGtms"][
        "teamsAndChannelsService"
    ]
    base_uri = f"{service_uri}/beta/users?top=999"
    users = []
    next_skiptoken = ""
    while True:
        uri = f"{base_uri}&skipToken={next_skiptoken}" if next_skiptoken else base_uri
        response = make_request(uri, access_token_id, "GET", "text", "")
        if not (
            response["response_status_code"] == 200
            and response["response_type"] == "json"
        ):
            return "[Error] Failed to list Teams users.", 400
        data = json.loads(response["response_text"])
        if "users" not in data:
            return "[Error] Failed to list Teams users.", 400
        users += data["users"]
        if "skipToken" not in data:
            return users
        next_skiptoken = data["skipToken"]


def get_user_details(access_token_id: int, user_id: str, external: bool = False):
    settings = get_settings(access_token_id)
    if not settings:
        return "[Error] Unable to obtain teams settings.", 400
    service_uri = json.loads(settings["teams_settings_raw"])["regionGtms"][
        "teamsAndChannelsService"
    ]
    uri = f"{service_uri}/beta/users/{user_id}"
    if external:
        uri += "/externalsearchv3"
    response = make_request(
        uri,
        access_token_id,
        "GET",
        "text",
        "",
        {"x-ms-client-version": "27/1.0.0.2020101241"},
    )
    if response["response_status_code"] == 200 and response["response_type"] == "json":
        return json.loads(response["response_text"])
    if response["response_status_code"] == 404:
        return f"[Error] User '{user_id}' not found.", 404
    return "[Error] Failed to get Teams user details.", 400


def create_conversation(
    access_token_id: int,
    members: list,
    conversation_type: str,
    topic: str = None,
    message_content: str = None,
):
    settings = get_settings(access_token_id)
    if not settings:
        return "[Error] Unable to obtain teams settings.", 400
    chat_service_uri = json.loads(settings["teams_settings_raw"])["regionGtms"][
        "chatService"
    ]
    uri = f"{chat_service_uri}/v1/threads"
    headers = {
        "Authentication": f"skypetoken={settings['skypeToken']}",
        "User-Agent": ua.get(),
    }
    base_members = [{"id": f"8:{settings['skype_id']}", "role": "Admin"}]
    properties = {
        "threadType": "chat",
        "chatFilesIndexId": "2",
        "fixedRoster": "true",
        "uniquerosterthread": (
            "true" if conversation_type == "direct_message" else "false"
        ),
    }
    if topic:
        properties["topic"] = topic
    created = []
    if conversation_type == "direct_message":
        for member in members:
            body = {
                "members": base_members + [{"id": member, "role": "Admin"}],
                "properties": properties,
            }
            response = requests.post(uri, headers=headers, json=body)
            if response.status_code < 300 and "Location" in response.headers:
                match = re.search(
                    r"https://.*?/v1/threads/(.*)$", response.headers["Location"]
                )
                if match:
                    created.append(match.group(1))
                    logger.debug("Created conversation with member {}. Conversation ID: {}", member, match.group(1))
                else:
                    logger.error("Failed creating direct message conversation with user {}. Received response status {}.", member, response.status_code)
            else:
                logger.error("Failed creating direct message conversation with user {}. Received response status {}.", member, response.status_code)
    elif conversation_type == "group_chat":
        body = {
            "members": base_members + [{"id": m, "role": "Admin"} for m in members],
            "properties": properties,
        }
        response = requests.post(uri, headers=headers, json=body)
        if response.status_code < 300 and "Location" in response.headers:
            match = re.search(
                r"https://.*?/v1/threads/(.*)$", response.headers["Location"]
            )
            if match:
                created.append(match.group(1))
                logger.debug("Created conversation with {} members. Conversation ID: {}", len(members), match.group(1))
            else:
                logger.error("Failed creating group chat conversation. Received response status {}", response.status_code)
        else:
            logger.error("Failed creating group chat conversation. Received response status {}", response.status_code)
    logger.debug("Created {} conversations.", len(created))
    if not created:
        return "[Error] Failed to create conversation(s).", 400
    if message_content:
        for conversation_id in created:
            conversation_link = f"{chat_service_uri}/v1/users/ME/conversations/{conversation_id}/messages"
            requests.post(
                conversation_link,
                headers=headers,
                json={"messagetype": "RichText/Html", "content": message_content},
            )
    return created
