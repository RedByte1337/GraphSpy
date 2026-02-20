# graphspy/api/teams.py

# Built-in imports
import json

# External library imports
from flask import Blueprint, Response, request

# Local library imports
from ..core import teams

bp = Blueprint("teams", __name__)


@bp.post("/api/get_teams_conversations")
def get_teams_conversations():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    return teams.get_conversations(access_token_id)


@bp.post("/api/get_teams_conversation_messages")
def get_teams_conversation_messages():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    conversation_link = request.form.get("conversation_link")
    if not conversation_link:
        return "[Error] No conversation_link specified.", 400
    return teams.get_conversation_messages(access_token_id, conversation_link)


@bp.post("/api/send_teams_conversation_message")
def send_teams_conversation_message():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    conversation_link = request.form.get("conversation_link")
    if not conversation_link:
        return "[Error] No conversation_link specified.", 400
    message_content = request.form.get("message_content")
    if not message_content:
        return "[Error] No message_content specified.", 400
    return teams.send_message(access_token_id, conversation_link, message_content)


@bp.post("/api/get_teams_conversation_members")
def get_teams_conversation_members():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    conversation_id = request.form.get("conversation_id")
    if not conversation_id:
        return "[Error] No conversation_id specified.", 400
    return teams.get_conversation_members(access_token_id, conversation_id)


@bp.get("/api/get_teams_image")
def get_teams_image():
    access_token_id = request.args.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    image_uri = request.args.get("image_uri")
    if not image_uri:
        return "[Error] No image_uri specified.", 400
    return teams.get_image(access_token_id, image_uri)


@bp.post("/api/list_teams_users")
def list_teams_users():
    access_token_id = request.form.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    return teams.list_users(access_token_id)


@bp.get("/api/get_teams_user_details")
def get_teams_user_details():
    access_token_id = request.args.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    user_id = request.args.get("user_id")
    if not user_id:
        return "[Error] No user_id specified.", 400
    external = request.args.get("external", "false").lower() == "true"
    return teams.get_user_details(access_token_id, user_id, external)


@bp.post("/api/create_teams_conversation")
def create_teams_conversation():
    if not request.is_json:
        return "[Error] Expecting JSON input.", 400
    data = request.get_json()
    access_token_id = data.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    members = data.get("members")
    if not members:
        return "[Error] No members specified.", 400
    conversation_type = data.get("type")
    if not conversation_type or conversation_type not in [
        "direct_message",
        "group_chat",
    ]:
        return "[Error] Type needs to be either 'direct_message' or 'group_chat'.", 400
    return teams.create_conversation(
        access_token_id,
        members,
        conversation_type,
        topic=data.get("topic"),
        message_content=data.get("message_content"),
    )
