# graphspy/api/entra.py

# Built-in imports
import json
import urllib.parse

# External library imports
from flask import Blueprint, request
from loguru import logger

# Local library imports
from ..core import requests_ as generic

bp = Blueprint("entra", __name__)


@bp.get("/api/get_entra_users")
def get_entra_users():
    access_token_id = request.args.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    customize_properties = request.args.get("customize_properties", "").strip()
    expand_memberships = bool(request.args.get("expand_memberships"))
    uri = "https://graph.microsoft.com/v1.0/users?$top=999"
    if customize_properties:
        uri += f"&$select={urllib.parse.quote_plus(customize_properties)}"
    if expand_memberships:
        uri += "&$expand=transitiveMemberOf"
    users_list = []
    for _ in range(5000):
        response = generic.make_request(uri, access_token_id, "GET", "text", "")
        if (
            response["response_status_code"] == 200
            and response["response_type"] == "json"
        ):
            response_json = json.loads(response["response_text"])
            users_list += response_json["value"]
            logger.debug(
                f"Retrieved {len(response_json['value'])} users. {len(users_list)} total users so far."
            )
            if "@odata.nextLink" in response_json:
                uri = response_json["@odata.nextLink"]
            else:
                logger.debug("All users retrieved.")
                break
        else:
            logger.error(
                f"Failed obtaining Entra ID Users. Status {response['response_status_code']}"
            )
            return (
                f"[Error] Failed obtaining Entra ID Users. Status {response['response_status_code']}",
                400,
            )
    return users_list


@bp.get("/api/get_entra_user_details/<user_id>")
def get_entra_user_details(user_id):
    access_token_id = request.args.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    parsed_user_id = urllib.parse.quote_plus(user_id)
    batch_body = {
        "requests": [
            {
                "id": "userDetails",
                "method": "GET",
                "url": f"/users/{parsed_user_id}?$expand=transitiveMemberOf&$select=displayName,givenName,surname,userPrincipalName,mail,otherMails,proxyAddresses,mobilePhone,businessPhones,faxNumber,createdDateTime,lastPasswordChangeDateTime,refreshTokensValidFromDateTime,userType,companyName,jobTitle,department,officeLocation,streetAddress,city,state,country,preferredLanguage,surname,userPrincipalName,id,accountEnabled,passwordPolicies,licenseAssignmentStates,creationType,customSecurityAttributes,onPremisesSyncEnabled,onPremisesDistinguishedName,onPremisesSamAccountName,onPremisesUserPrincipalName,onPremisesDomainName,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSecurityIdentifier,securityIdentifier",
            },
            {
                "id": "ownedObjects",
                "method": "GET",
                "url": f"/users/{parsed_user_id}/ownedObjects",
            },
            {
                "id": "ownedDevices",
                "method": "GET",
                "url": f"/users/{parsed_user_id}/ownedDevices",
            },
            {
                "id": "appRoleAssignments",
                "method": "GET",
                "url": f"/users/{parsed_user_id}/appRoleAssignments",
            },
            {
                "id": "oauth2PermissionGrants",
                "method": "GET",
                "url": f"/users/{parsed_user_id}/oauth2PermissionGrants",
            },
        ]
    }
    response = generic.make_request(
        "https://graph.microsoft.com/v1.0/$batch",
        access_token_id,
        "POST",
        "json",
        batch_body,
    )
    if not (
        response["response_status_code"] == 200 and response["response_type"] == "json"
    ):
        logger.error(
            f"Something went wrong trying to obtain user details of '{user_id}'."
        )
        return (
            f"[Error] Failed obtaining user details for '{user_id}'. Status {response['response_status_code']}",
            400,
        )
    batch_responses = json.loads(response["response_text"])["responses"]
    user_details_list = [
        r["body"]
        for r in batch_responses
        if r["id"] == "userDetails" and r["status"] == 200
    ]
    if not user_details_list:
        logger.error(
            f"Something went wrong trying to obtain user details of '{user_id}'."
        )
        return f"[Error] Failed obtaining user details for '{user_id}'.", 400
    user_details = user_details_list[0]
    for r in batch_responses:
        if r["id"] == "userDetails":
            continue
        user_details[r["id"]] = r["body"].get("value", [])
    return user_details
