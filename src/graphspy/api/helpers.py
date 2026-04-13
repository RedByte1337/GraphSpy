# graphspy/api/helpers.py

# External library imports
from flask import jsonify


def create_response(status_code: int, message: str = None, data=None):
    body = {}
    if message is not None:
        body["message"] = message
    if data is not None:
        body["data"] = data
    return jsonify(body), status_code
