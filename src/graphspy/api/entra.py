# graphspy/api/entra.py

# Built-in imports
import json
import urllib.parse

# External library imports
from flask import Blueprint, request
from loguru import logger

# Local library imports
from ..core import requests_ as gspy_requests

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
        response = gspy_requests.generic_request(uri, access_token_id, "GET", "text", "")
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
    response = gspy_requests.generic_request(
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
    # Check if any response has status 429 (throttled)
    throttled_responses = [response for response in batch_responses if response["status"] == 429]
    if len(throttled_responses) > 0:
        logger.error(f"Request throttled (429) when trying to obtain user details of '{user_id}'.")
        logger.error(response)
        return f"[Error] Request throttled (429) by Microsoft when trying to obtain user details of '{user_id}'. Please try again later.", 429
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


@bp.get("/api/get_entra_group_details/<group_id>")
def get_entra_group_details(group_id):
    if not "access_token_id" in request.args:
        return f"[Error] No access_token_id specified.", 400
    access_token_id = request.args['access_token_id']
    parsed_group_id = urllib.parse.quote_plus(group_id)
    batch_body = {
        "requests": [
            {
                "id": "groupDetails",
                "method": "GET",
                "url": f"/groups/{parsed_group_id}"
            },
            {
                "id": "transitiveMembers",
                "method": "GET",
                "url": f"/groups/{parsed_group_id}/transitiveMembers"
            },
            {
                "id": "owners",
                "method": "GET",
                "url": f"/groups/{parsed_group_id}/owners"
            },
            {
                "id": "transitiveMemberOf",
                "method": "GET",
                "url": f"/groups/{parsed_group_id}/transitiveMemberOf"
            },
            {
                "id": "drives",
                "method": "GET",
                "url": f"/groups/{parsed_group_id}/drives"
            },
            {
                "id": "team",
                "method": "GET",
                "url": f"/groups/{parsed_group_id}/team"
            },
            {
                "id": "sites",
                "method": "GET",
                "url": f"/groups/{parsed_group_id}/sites"
            },
            {
                "id": "appRoleAssignments",
                "method": "GET",
                "url": f"/groups/{parsed_group_id}/appRoleAssignments"
            }
        ]
    }
    batch_uri = "https://graph.microsoft.com/v1.0/$batch"
    batch_response = gspy_requests.generic_request(batch_uri, access_token_id, "POST", "json", batch_body)
    if not (batch_response['response_status_code'] == 200 and batch_response['response_type'] == "json"):
        logger.error(f"Something went wrong trying to obtain group details of '{group_id}'.")
        logger.error(batch_response)
        return f"[Error] Something went wrong trying to obtain group details of '{group_id}'. Received response status {batch_response['response_status_code']} and response type {batch_response['response_type']}", 400
    batch_response_list = json.loads(batch_response['response_text'])["responses"]
    # Check if any response has status 429 (throttled)
    throttled_responses = [response for response in batch_response_list if response["status"] == 429]
    if len(throttled_responses) > 0:
        logger.error(f"Request throttled (429) when trying to obtain group details of '{group_id}'.")
        logger.error(batch_response)
        return f"[Error] Request throttled (429) by Microsoft when trying to obtain group details of '{group_id}'. Please try again later.", 429
    group_details = [response["body"] for response in batch_response_list if response["id"] == "groupDetails" and response["status"] == 200]
    if len(group_details) == 0:
        logger.error(f"Something went wrong trying to obtain group details of '{group_id}'.")
        logger.error(batch_response)
        return f"[Error] Something went wrong trying to obtain group details of '{group_id}'.", 400
    group_details = group_details[0]
    for response in batch_response_list:
        if response["id"] == "groupDetails":
            continue
        # Handle 404 errors gracefully (e.g., team might not exist for all groups)
        if response["status"] == 200:
            group_details[response["id"]] = response["body"]["value"] if "value" in response["body"] else response["body"]
        else:
            group_details[response["id"]] = []
    return group_details

@bp.get("/api/get_entra_groups")
def get_entra_groups():
    if not "access_token_id" in request.args:
        return f"[Error] No access_token_id specified.", 400
    access_token_id = request.args['access_token_id']
    uri = f"https://graph.microsoft.com/v1.0/groups?$top=999&$expand=transitiveMembers($select=id,displayName,userPrincipalName)"
    if "customize_properties" in request.args and request.args["customize_properties"] != " ":
        uri += f"&$select={urllib.parse.quote_plus(request.args['customize_properties'])}"
    groups_list = []
    for x in range(5000):
        response = gspy_requests.generic_request(uri, access_token_id, "GET", "text", "")
        if response['response_status_code'] == 200 and response['response_type'] == "json":
            response_json = json.loads(response['response_text'])
            groups_list += response_json["value"]
            logger.debug(f"Retrieved {len(response_json['value'])} groups. {len(groups_list)} total groups so far.")
            if "@odata.nextLink" in response_json:
                uri = response_json["@odata.nextLink"]
            else:
                logger.debug(f"All groups retrieved.")
                break
        else:
            logger.error(response)
            return f"[Error] Something went wrong trying to obtain Entra ID Groups. Received response status {response['response_status_code']} and response type {response['response_type']}", 400
    return groups_list


@bp.get("/api/get_entra_roles")
def get_entra_roles():
    if not "access_token_id" in request.args:
        return f"[Error] No access_token_id specified.", 400
    access_token_id = request.args['access_token_id']

    role_assignments_list = []
    pim_headers = {"ConsistencyLevel": "eventual"}

    # Get Active role assignments via Graph beta PIM endpoint
    uri_active = "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleInstances?$expand=activatedUsing,principal,roleDefinition,directoryScope&$orderby=roleDefinition/displayName asc&$count=true&$top=999"
    for x in range(5000):
        response = gspy_requests.generic_request(uri_active, access_token_id, "GET", "text", "", headers=pim_headers)
        if response['response_status_code'] == 200 and response['response_type'] == "json":
            response_json = json.loads(response['response_text'])
            for item in response_json["value"]:
                role_assignments_list.append(_normalize_role_assignment(item, "Active"))
            logger.debug(f"Retrieved {len(response_json['value'])} active role assignments. {len(role_assignments_list)} total role assignments so far.")
            if "@odata.nextLink" in response_json:
                uri_active = response_json["@odata.nextLink"]
            else:
                logger.debug(f"All active role assignments retrieved.")
                break
        else:
            logger.error(response)
            return f"[Error] Something went wrong trying to obtain Entra ID Active Roles. Received response status {response['response_status_code']} and response type {response['response_type']}", 400

    # Get Eligible role assignments via Graph beta PIM endpoint
    uri_eligible = "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal,roleDefinition,directoryScope&$orderby=roleDefinition/displayName asc&$count=true&$top=999"
    for x in range(5000):
        response = gspy_requests.generic_request(uri_eligible, access_token_id, "GET", "text", "", headers=pim_headers)
        if response['response_status_code'] == 200 and response['response_type'] == "json":
            response_json = json.loads(response['response_text'])
            for item in response_json["value"]:
                role_assignments_list.append(_normalize_role_assignment(item, "Eligible"))
            logger.debug(f"Retrieved {len(response_json['value'])} eligible role assignments. {len(role_assignments_list)} total role assignments so far.")
            if "@odata.nextLink" in response_json:
                uri_eligible = response_json["@odata.nextLink"]
            else:
                logger.debug(f"All eligible role assignments retrieved.")
                break
        else:
            logger.error(response)
            return f"[Error] Something went wrong trying to obtain Entra ID Eligible Roles. Received response status {response['response_status_code']} and response type {response['response_type']}", 400

    return role_assignments_list


_ODATA_TYPE_MAP = {
    "#microsoft.graph.user": "User",
    "#microsoft.graph.group": "Group",
    "#microsoft.graph.servicePrincipal": "ServicePrincipal",
}


def _normalize_role_assignment(item: dict, assignment_state: str) -> dict:
    """Normalize a Graph beta PIM response item to match the UI column contract."""
    principal = item.get("principal", {})
    odata_type = principal.get("@odata.type", "")
    return {
        "roleDefinition": {
            "displayName": (item.get("roleDefinition") or {}).get("displayName", ""),
        },
        "subject": {
            "displayName": principal.get("displayName", ""),
            "type": _ODATA_TYPE_MAP.get(odata_type, odata_type),
            "principalName": principal.get("userPrincipalName", ""),
        },
        "assignmentState": assignment_state,
        "memberType": item.get("memberType", ""),
        "scopedResource": {
            "displayName": (item.get("directoryScope") or {}).get("displayName", ""),
        },
        "startDateTime": item.get("startDateTime", ""),
        "endDateTime": item.get("endDateTime", ""),
        "isPermanent": item.get("endDateTime") is None,
    }