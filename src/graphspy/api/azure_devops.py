# graphspy/api/azure_devops.py

# Built-in imports
import base64
import json

# External library imports
from flask import Blueprint, request
from loguru import logger

# Local library imports
from ..core import requests_ as gspy_requests
from ..db import connection

bp = Blueprint("azure_devops", __name__)

# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

_VSSPS_BASE = "https://app.vssps.visualstudio.com"
_VSSPS_ORG_BASE = "https://vssps.dev.azure.com"
_ADO_BASE = "https://dev.azure.com"
_VSAEX_BASE = "https://vsaex.dev.azure.com"
_VSRM_BASE = "https://vsrm.dev.azure.com"
_ADO_AUDIT_BASE = "https://auditservice.dev.azure.com"
_VSSPS_PROFILE = "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.1"


def _get_token_value(access_token_id: str) -> str | None:
    """Return the raw token string for an access token ID."""
    row = connection.query_db(
        "SELECT accesstoken FROM accesstokens WHERE id = ?",
        [access_token_id],
        one=True,
    )
    return row[0] if row else None


def _ado_get(url: str, access_token_id: str) -> dict:
    """Wrapper around generic_request for Azure DevOps GET calls."""
    return gspy_requests.generic_request(url, access_token_id, "GET", "text", "")


def _paginate_ado(base_url: str, access_token_id: str, value_key: str = "value") -> tuple[list, str | None]:
    """
    Retrieve all pages from an Azure DevOps list endpoint.
    Returns (items_list, error_message_or_None).
    """
    items = []
    url = base_url
    for _ in range(500):
        resp = _ado_get(url, access_token_id)
        if resp["response_status_code"] != 200 or resp["response_type"] != "json":
            err = (
                f"[Error] Status {resp['response_status_code']}: "
                f"{resp['response_text'][:300]}"
            )
            return items, err
        body = json.loads(resp["response_text"])
        batch = body.get(value_key) if value_key else body
        if isinstance(batch, list):
            items.extend(batch)
        elif batch is not None:
            items.append(batch)
        continuation = resp["response_headers"].get("X-MS-ContinuationToken")
        if not continuation:
            break
        sep = "&" if "?" in url else "?"
        url = f"{base_url}{sep}continuationToken={continuation}"
    return items, None


# ------------------------------------------------------------------
# Profile & Organizations
# ------------------------------------------------------------------

@bp.get("/api/azdevops/profile")
def azdevops_profile():
    access_token_id = request.args.get("access_token_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400

    resp = _ado_get(_VSSPS_PROFILE, access_token_id)
    sc = resp["response_status_code"]
    if sc != 200 or resp["response_type"] != "json":
        if sc in (401, 403):
            msg = f"[Error] Unauthorized (Status {sc}). The access token is invalid, expired, or missing the Azure DevOps audience."
        elif sc == 203:
            msg = f"[Error] Access token is expired or invalid (Status 203 Non-Authoritative). Please reload with a valid token."
        else:
            msg = f"[Error] Failed to fetch Azure DevOps profile. Status {sc}: {resp['response_text'][:200]}"
        logger.error(f"AzDevOps profile fetch failed. Status {sc}: {resp['response_text'][:200]}")
        return msg, 400
    profile = json.loads(resp["response_text"])
    logger.debug(f"AzDevOps profile fetched for publicAlias={profile.get('publicAlias')}")
    return profile


@bp.get("/api/azdevops/organizations")
def azdevops_organizations():
    access_token_id = request.args.get("access_token_id")
    member_id = request.args.get("member_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not member_id:
        return "[Error] No member_id specified.", 400

    url = f"{_VSSPS_BASE}/_apis/accounts?memberId={member_id}&api-version=7.1"
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        logger.error(
            f"AzDevOps organizations fetch failed. Status {resp['response_status_code']}: "
            f"{resp['response_text'][:300]}"
        )
        return (
            f"[Error] Failed to fetch organizations. Status {resp['response_status_code']}.",
            400,
        )
    body = json.loads(resp["response_text"])
    orgs = body.get("value", [])
    logger.debug(f"AzDevOps: retrieved {len(orgs)} organization(s) for memberId={member_id}")
    return orgs


# ------------------------------------------------------------------
# Projects
# ------------------------------------------------------------------

@bp.get("/api/azdevops/projects")
def azdevops_projects():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org:
        return "[Error] No org specified.", 400

    url = f"{_ADO_BASE}/{org}/_apis/projects?$top=500&api-version=7.1"
    items, err = _paginate_ado(url, access_token_id)
    if err:
        logger.error(f"AzDevOps projects fetch failed for org={org}: {err}")
        return err, 400
    logger.debug(f"AzDevOps: retrieved {len(items)} project(s) for org={org}")
    return items


# ------------------------------------------------------------------
# Repositories
# ------------------------------------------------------------------

@bp.get("/api/azdevops/repos")
def azdevops_repos():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org or not project:
        return "[Error] org and project are required.", 400

    url = (
        f"{_ADO_BASE}/{org}/{project}/_apis/git/repositories"
        f"?includeLinks=true&api-version=7.1"
    )
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        logger.error(
            f"AzDevOps repos fetch failed org={org} project={project}. "
            f"Status {resp['response_status_code']}"
        )
        return (
            f"[Error] Failed to list repositories. Status {resp['response_status_code']}.",
            400,
        )
    body = json.loads(resp["response_text"])
    repos = body.get("value", [])
    logger.debug(f"AzDevOps: retrieved {len(repos)} repo(s) for org={org} project={project}")
    return repos


# ------------------------------------------------------------------
# Repo Browser: items, file content, branches, commits, push, download
# ------------------------------------------------------------------

@bp.get("/api/azdevops/repo_items")
def azdevops_repo_items():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    repo_id = request.args.get("repo_id")
    path = request.args.get("path", "/")
    branch = request.args.get("branch", "")
    if not access_token_id or not org or not project or not repo_id:
        return "[Error] access_token_id, org, project, repo_id required.", 400
    version_param = f"&versionDescriptor.version={branch}" if branch else ""
    url = (
        f"{_ADO_BASE}/{org}/{project}/_apis/git/repositories/{repo_id}/items"
        f"?scopePath={path}&recursionLevel=OneLevel&includeContentMetadata=true"
        f"{version_param}&api-version=7.1"
    )
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        return f"[Error] Status {resp['response_status_code']}: {resp['response_text'][:300]}", 400
    body = json.loads(resp["response_text"])
    return body.get("value", [])


@bp.get("/api/azdevops/repo_file")
def azdevops_repo_file():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    repo_id = request.args.get("repo_id")
    path = request.args.get("path", "/")
    branch = request.args.get("branch", "")
    if not access_token_id or not org or not project or not repo_id:
        return "[Error] access_token_id, org, project, repo_id required.", 400
    version_param = f"&versionDescriptor.version={branch}" if branch else ""
    url = (
        f"{_ADO_BASE}/{org}/{project}/_apis/git/repositories/{repo_id}/items"
        f"?path={path}&download=false{version_param}&api-version=7.1"
    )
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200:
        return f"[Error] Status {resp['response_status_code']}: {resp['response_text'][:300]}", 400
    return {"content": resp["response_text"]}


@bp.get("/api/azdevops/repo_branches")
def azdevops_repo_branches():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    repo_id = request.args.get("repo_id")
    if not access_token_id or not org or not project or not repo_id:
        return "[Error] access_token_id, org, project, repo_id required.", 400
    url = f"{_ADO_BASE}/{org}/{project}/_apis/git/repositories/{repo_id}/refs?filter=heads&api-version=7.1"
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        return f"[Error] Status {resp['response_status_code']}: {resp['response_text'][:300]}", 400
    body = json.loads(resp["response_text"])
    return body.get("value", [])


@bp.get("/api/azdevops/repo_commits")
def azdevops_repo_commits():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    repo_id = request.args.get("repo_id")
    branch = request.args.get("branch", "")
    if not access_token_id or not org or not project or not repo_id:
        return "[Error] access_token_id, org, project, repo_id required.", 400
    branch_param = f"&searchCriteria.itemVersion.version={branch}" if branch else ""
    url = (
        f"{_ADO_BASE}/{org}/{project}/_apis/git/repositories/{repo_id}/commits"
        f"?$top=100{branch_param}&api-version=7.1"
    )
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        return f"[Error] Status {resp['response_status_code']}: {resp['response_text'][:300]}", 400
    body = json.loads(resp["response_text"])
    return body.get("value", [])


@bp.post("/api/azdevops/repo_push")
def azdevops_repo_push():
    """Update a single file via a Git push."""
    access_token_id = request.form.get("access_token_id")
    org = request.form.get("org")
    project = request.form.get("project")
    repo_id = request.form.get("repo_id")
    path = request.form.get("path")
    content = request.form.get("content", "")
    branch = request.form.get("branch", "main")
    commit_msg = request.form.get("commit_msg", "Updated via GraphSpy")
    if not all([access_token_id, org, project, repo_id, path]):
        return "[Error] access_token_id, org, project, repo_id, path required.", 400

    # Get current branch ref to retrieve oldObjectId
    ref_url = f"{_ADO_BASE}/{org}/{project}/_apis/git/repositories/{repo_id}/refs?filter=heads/{branch}&api-version=7.1"
    ref_resp = _ado_get(ref_url, access_token_id)
    if ref_resp["response_status_code"] != 200 or ref_resp["response_type"] != "json":
        return f"[Error] Could not get branch ref. Status {ref_resp['response_status_code']}.", 400
    refs = json.loads(ref_resp["response_text"]).get("value", [])
    if not refs:
        return f"[Error] Branch '{branch}' not found.", 400
    old_object_id = refs[0]["objectId"]

    push_body = {
        "refUpdates": [{"name": f"refs/heads/{branch}", "oldObjectId": old_object_id}],
        "commits": [{
            "comment": commit_msg,
            "changes": [{
                "changeType": "edit",
                "item": {"path": path},
                "newContent": {"content": content, "contentType": "rawtext"}
            }]
        }]
    }
    push_url = f"{_ADO_BASE}/{org}/{project}/_apis/git/repositories/{repo_id}/pushes?api-version=7.1"
    token_val = _get_token_value(access_token_id)
    if not token_val:
        return "[Error] Token not found.", 400
    import requests as _requests
    r = _requests.post(
        push_url,
        json=push_body,
        headers={"Authorization": f"Bearer {token_val}", "Content-Type": "application/json"}
    )
    if r.status_code not in (200, 201):
        logger.error(f"AzDevOps push failed: {r.status_code} {r.text[:300]}")
        return f"[Error] Push failed. Status {r.status_code}: {r.text[:200]}", 400
    logger.debug(f"AzDevOps: pushed change to {path} in repo={repo_id}")
    return {"success": True}


@bp.get("/api/azdevops/repo_download")
def azdevops_repo_download():
    """Proxy-download repository as a zip archive."""
    from flask import Response, stream_with_context
    import requests as _requests
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    repo_id = request.args.get("repo_id")
    repo_name = request.args.get("repo_name", "repo")
    branch = request.args.get("branch", "")
    if not access_token_id or not org or not project or not repo_id:
        return "[Error] access_token_id, org, project, repo_id required.", 400
    token_val = _get_token_value(access_token_id)
    if not token_val:
        return "[Error] Token not found.", 400
    # $format=zip is required — without it the API returns JSON, not a zip
    version_param = f"&versionDescriptor.version={branch}" if branch else ""
    url = (
        f"{_ADO_BASE}/{org}/{project}/_apis/git/repositories/{repo_id}/items"
        f"?scopePath=/&download=true&recursionLevel=full&$format=zip{version_param}&api-version=7.1"
    )
    r = _requests.get(url, headers={"Authorization": f"Bearer {token_val}"}, stream=True, allow_redirects=True)
    if r.status_code != 200:
        logger.error(f"AzDevOps repo_download failed: {r.status_code} {r.text[:200]}")
        return f"[Error] Download failed. Status {r.status_code}.", 400
    def generate():
        for chunk in r.iter_content(chunk_size=65536):
            yield chunk
    return Response(
        stream_with_context(generate()),
        content_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{repo_name}.zip"'}
    )


# ------------------------------------------------------------------
# Pipelines / Builds
# ------------------------------------------------------------------

@bp.get("/api/azdevops/pipelines")
def azdevops_pipelines():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org or not project:
        return "[Error] org and project are required.", 400

    url = f"{_ADO_BASE}/{org}/{project}/_apis/pipelines?$top=500&api-version=7.1"
    items, err = _paginate_ado(url, access_token_id)
    if err:
        logger.error(f"AzDevOps pipelines fetch failed org={org} project={project}: {err}")
        return err, 400
    logger.debug(f"AzDevOps: retrieved {len(items)} pipeline(s) for org={org} project={project}")
    return items


@bp.get("/api/azdevops/pipeline_runs")
def azdevops_pipeline_runs():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    pipeline_id = request.args.get("pipeline_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org or not project or not pipeline_id:
        return "[Error] org, project and pipeline_id are required.", 400

    url = (
        f"{_ADO_BASE}/{org}/{project}/_apis/pipelines/{pipeline_id}/runs"
        f"?$top=50&api-version=7.1"
    )
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        logger.error(
            f"AzDevOps pipeline runs fetch failed pipeline={pipeline_id}. "
            f"Status {resp['response_status_code']}"
        )
        return (
            f"[Error] Failed to list pipeline runs. Status {resp['response_status_code']}.",
            400,
        )
    body = json.loads(resp["response_text"])
    runs = body.get("value", [])
    logger.debug(
        f"AzDevOps: retrieved {len(runs)} run(s) for pipeline={pipeline_id} org={org} project={project}"
    )
    return runs


@bp.get("/api/azdevops/pipeline_yaml")
def azdevops_pipeline_yaml():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    pipeline_id = request.args.get("pipeline_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org or not project or not pipeline_id:
        return "[Error] org, project and pipeline_id are required.", 400

    url = (
        f"{_ADO_BASE}/{org}/{project}/_apis/pipelines/{pipeline_id}"
        f"?api-version=7.1"
    )
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        logger.error(
            f"AzDevOps pipeline YAML fetch failed pipeline={pipeline_id}. "
            f"Status {resp['response_status_code']}"
        )
        return (
            f"[Error] Failed to fetch pipeline definition. Status {resp['response_status_code']}.",
            400,
        )
    body = json.loads(resp["response_text"])
    logger.debug(f"AzDevOps: fetched pipeline definition for pipeline={pipeline_id}")
    return body


@bp.get("/api/azdevops/build_logs")
def azdevops_build_logs():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    build_id = request.args.get("build_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org or not project or not build_id:
        return "[Error] org, project and build_id are required.", 400

    url = (
        f"{_ADO_BASE}/{org}/{project}/_apis/build/builds/{build_id}/logs"
        f"?api-version=7.1"
    )
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        logger.error(
            f"AzDevOps build logs fetch failed build={build_id}. "
            f"Status {resp['response_status_code']}"
        )
        return (
            f"[Error] Failed to fetch build logs. Status {resp['response_status_code']}.",
            400,
        )
    body = json.loads(resp["response_text"])
    logs = body.get("value", [])
    logger.debug(f"AzDevOps: retrieved {len(logs)} log entries for build={build_id}")
    return logs


# ------------------------------------------------------------------
# Teams & Members
# ------------------------------------------------------------------

@bp.get("/api/azdevops/teams")
def azdevops_teams():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org or not project:
        return "[Error] org and project are required.", 400

    url = (
        f"{_ADO_BASE}/{org}/_apis/projects/{project}/teams"
        f"?$top=200&api-version=7.1"
    )
    items, err = _paginate_ado(url, access_token_id)
    if err:
        logger.error(f"AzDevOps teams fetch failed org={org} project={project}: {err}")
        return err, 400
    logger.debug(f"AzDevOps: retrieved {len(items)} team(s) for org={org} project={project}")
    return items


@bp.get("/api/azdevops/team_members")
def azdevops_team_members():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    team_id = request.args.get("team_id")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org or not project or not team_id:
        return "[Error] org, project and team_id are required.", 400

    url = (
        f"{_ADO_BASE}/{org}/_apis/projects/{project}/teams/{team_id}/members"
        f"?api-version=7.1"
    )
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        logger.error(
            f"AzDevOps team members fetch failed team={team_id}. "
            f"Status {resp['response_status_code']}"
        )
        return (
            f"[Error] Failed to list team members. Status {resp['response_status_code']}.",
            400,
        )
    body = json.loads(resp["response_text"])
    members = body.get("value", [])
    logger.debug(f"AzDevOps: retrieved {len(members)} member(s) for team={team_id}")
    return members


# ------------------------------------------------------------------
# Users & Groups (org-level)
# ------------------------------------------------------------------

@bp.get("/api/azdevops/users")
def azdevops_users():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org:
        return "[Error] org is required.", 400

    url = f"{_VSAEX_BASE}/{org}/_apis/userentitlements?$top=500&api-version=7.1-preview.3"
    items, err = _paginate_ado(url, access_token_id, value_key="members")
    if err:
        logger.error(f"AzDevOps users fetch failed org={org}: {err}")
        return err, 400
    logger.debug(f"AzDevOps: retrieved {len(items)} user(s) for org={org}")
    return items


@bp.get("/api/azdevops/groups")
def azdevops_groups():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org:
        return "[Error] org is required.", 400

    url = (
        f"https://vssps.dev.azure.com/{org}/_apis/graph/groups"
        f"?api-version=7.1-preview.1"
    )
    items, err = _paginate_ado(url, access_token_id)
    if err:
        logger.error(f"AzDevOps groups fetch failed org={org}: {err}")
        return err, 400
    logger.debug(f"AzDevOps: retrieved {len(items)} group(s) for org={org}")
    return items


@bp.get("/api/azdevops/group_members")
def azdevops_group_members():
    import requests as _requests
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    group_descriptor = request.args.get("group_descriptor")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org or not group_descriptor:
        return "[Error] org and group_descriptor are required.", 400

    url = (
        f"https://vssps.dev.azure.com/{org}/_apis/graph/memberships/{group_descriptor}"
        f"?direction=down&api-version=7.1-preview.1"
    )
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        logger.error(
            f"AzDevOps group members fetch failed group={group_descriptor}. "
            f"Status {resp['response_status_code']}"
        )
        return (
            f"[Error] Failed to list group members. Status {resp['response_status_code']}.",
            400,
        )
    body = json.loads(resp["response_text"])
    members = body.get("value", [])

    # Resolve member descriptors → display names via subjects/lookup
    descriptors = [m["memberDescriptor"] for m in members if m.get("memberDescriptor")]
    if descriptors:
        token_val = _get_token_value(access_token_id)
        lookup_url = f"https://vssps.dev.azure.com/{org}/_apis/graph/subjects/lookup?api-version=7.1-preview.1"
        try:
            lresp = _requests.post(
                lookup_url,
                json={"lookupKeys": [{"descriptor": d} for d in descriptors]},
                headers={"Authorization": f"Bearer {token_val}", "Content-Type": "application/json"},
                timeout=10,
            )
            if lresp.status_code == 200:
                lookup_map = lresp.json().get("value", {})
                for m in members:
                    md = m.get("memberDescriptor", "")
                    if md in lookup_map:
                        subj = lookup_map[md]
                        m["_displayName"] = subj.get("displayName", "")
                        m["_principalName"] = subj.get("principalName") or subj.get("mailAddress", "")
                        m["_subjectKind"] = subj.get("subjectKind", "")
        except Exception as exc:
            logger.debug(f"AzDevOps subjects/lookup skipped: {exc}")

    logger.debug(f"AzDevOps: retrieved {len(members)} member(s) for group={group_descriptor}")
    return members


# ------------------------------------------------------------------
# Service Connections
# ------------------------------------------------------------------

@bp.get("/api/azdevops/service_connections")
def azdevops_service_connections():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org or not project:
        return "[Error] org and project are required.", 400

    url = (
        f"{_ADO_BASE}/{org}/{project}/_apis/serviceendpoint/endpoints"
        f"?api-version=7.1-preview.4"
    )
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        logger.error(
            f"AzDevOps service connections fetch failed org={org} project={project}. "
            f"Status {resp['response_status_code']}"
        )
        return (
            f"[Error] Failed to list service connections. Status {resp['response_status_code']}.",
            400,
        )
    body = json.loads(resp["response_text"])
    connections = body.get("value", [])
    logger.debug(
        f"AzDevOps: retrieved {len(connections)} service connection(s) for org={org} project={project}"
    )
    return connections


# ------------------------------------------------------------------
# Variable Groups (potential secrets)
# ------------------------------------------------------------------

@bp.get("/api/azdevops/variable_groups")
def azdevops_variable_groups():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org or not project:
        return "[Error] org and project are required.", 400

    url = (
        f"{_ADO_BASE}/{org}/{project}/_apis/distributedtask/variablegroups"
        f"?api-version=7.1-preview.2"
    )
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        logger.error(
            f"AzDevOps variable groups fetch failed org={org} project={project}. "
            f"Status {resp['response_status_code']}"
        )
        return (
            f"[Error] Failed to list variable groups. Status {resp['response_status_code']}.",
            400,
        )
    body = json.loads(resp["response_text"])
    groups = body.get("value", [])
    logger.debug(
        f"AzDevOps: retrieved {len(groups)} variable group(s) for org={org} project={project}"
    )
    return groups


# ------------------------------------------------------------------
# Secure Files
# ------------------------------------------------------------------

@bp.get("/api/azdevops/secure_files")
def azdevops_secure_files():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org or not project:
        return "[Error] org and project are required.", 400

    url = (
        f"{_ADO_BASE}/{org}/{project}/_apis/distributedtask/securefiles"
        f"?api-version=7.1-preview.1"
    )
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        logger.error(
            f"AzDevOps secure files fetch failed org={org} project={project}. "
            f"Status {resp['response_status_code']}"
        )
        return (
            f"[Error] Failed to list secure files. Status {resp['response_status_code']}.",
            400,
        )
    body = json.loads(resp["response_text"])
    files = body.get("value", [])
    logger.debug(
        f"AzDevOps: retrieved {len(files)} secure file(s) for org={org} project={project}"
    )
    return files


# ------------------------------------------------------------------
# Environments (deployment)
# ------------------------------------------------------------------

@bp.get("/api/azdevops/environments")
def azdevops_environments():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    project = request.args.get("project")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org or not project:
        return "[Error] org and project are required.", 400

    url = (
        f"{_ADO_BASE}/{org}/{project}/_apis/distributedtask/environments"
        f"?$top=200&api-version=7.1-preview.1"
    )
    items, err = _paginate_ado(url, access_token_id)
    if err:
        logger.error(f"AzDevOps environments fetch failed org={org} project={project}: {err}")
        return err, 400
    logger.debug(
        f"AzDevOps: retrieved {len(items)} environment(s) for org={org} project={project}"
    )
    return items


# ------------------------------------------------------------------
# Agent Pools
# ------------------------------------------------------------------

@bp.get("/api/azdevops/agent_pools")
def azdevops_agent_pools():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org:
        return "[Error] org is required.", 400

    url = (
        f"{_ADO_BASE}/{org}/_apis/distributedtask/pools"
        f"?api-version=7.1"
    )
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        logger.error(
            f"AzDevOps agent pools fetch failed org={org}. "
            f"Status {resp['response_status_code']}"
        )
        return (
            f"[Error] Failed to list agent pools. Status {resp['response_status_code']}.",
            400,
        )
    body = json.loads(resp["response_text"])
    pools = body.get("value", [])
    logger.debug(f"AzDevOps: retrieved {len(pools)} agent pool(s) for org={org}")
    return pools


# ------------------------------------------------------------------
# Audit Log
# ------------------------------------------------------------------

@bp.get("/api/azdevops/audit_log")
def azdevops_audit_log():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    start_time = request.args.get("start_time", "")
    batch_size = request.args.get("batch_size", "200")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org:
        return "[Error] org is required.", 400

    url = (
        f"{_ADO_AUDIT_BASE}/{org}/_apis/audit/auditlog"
        f"?batchSize={batch_size}&api-version=7.1-preview.1"
    )
    if start_time:
        url += f"&startTime={start_time}"

    items, err = _paginate_ado(url, access_token_id, value_key="decoratedAuditLogEntries")
    if err:
        logger.error(f"AzDevOps audit log fetch failed org={org}: {err}")
        return err, 400
    logger.debug(f"AzDevOps: retrieved {len(items)} audit log entry(ies) for org={org}")
    return items


# ------------------------------------------------------------------
# Personal Access Tokens (listing own PATs)
# ------------------------------------------------------------------

@bp.get("/api/azdevops/tokens")
def azdevops_tokens():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org", "")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400

    # PAT listing is org-scoped on vssps.dev.azure.com
    base = f"{_VSSPS_ORG_BASE}/{org}" if org else _VSSPS_BASE
    url = f"{base}/_apis/tokens/pats?displayFilterOption=active&api-version=7.1-preview.1"
    items, err = _paginate_ado(url, access_token_id, value_key="patTokens")
    if err:
        logger.error(f"AzDevOps PAT listing failed: {err}")
        return err, 400
    logger.debug(f"AzDevOps: retrieved {len(items)} PAT(s)")
    return items


# ------------------------------------------------------------------
# Current user entitlement (Status + Access Level)
# ------------------------------------------------------------------

@bp.get("/api/azdevops/my_entitlement")
def azdevops_my_entitlement():
    """
    Get the current user's entitlement (Status + Access Level) by member ID.
    The /me route does not exist; we look up by member_id instead.
    """
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    member_id = request.args.get("member_id", "")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org:
        return "[Error] org is required.", 400

    # Use member_id if provided; else fall back to listing and picking first result
    if member_id:
        url = f"{_VSAEX_BASE}/{org}/_apis/userentitlements/{member_id}?api-version=7.1-preview.3"
    else:
        url = f"{_VSAEX_BASE}/{org}/_apis/userentitlements?$top=1&api-version=7.1-preview.3"
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        # Token already validated by profile call — any failure here means restricted access
        logger.debug(f"AzDevOps my_entitlement: status={resp['response_status_code']} for org={org}, returning partial")
        return {"_restricted": True, "accessLevel": {"status": "Active", "licenseDisplayName": "Stakeholder / Restricted"}}
    entitlement = json.loads(resp["response_text"])
    if "members" in entitlement:
        members = entitlement.get("members", [])
        entitlement = members[0] if members else {}
    logger.debug(f"AzDevOps: fetched entitlement for org={org}")
    return entitlement


# ------------------------------------------------------------------
# Security Namespaces (org-level permissions)
# ------------------------------------------------------------------

@bp.get("/api/azdevops/security_namespaces")
def azdevops_security_namespaces():
    access_token_id = request.args.get("access_token_id")
    org = request.args.get("org")
    if not access_token_id:
        return "[Error] No access_token_id specified.", 400
    if not org:
        return "[Error] org is required.", 400

    url = f"{_ADO_BASE}/{org}/_apis/securitynamespaces?api-version=7.1"
    resp = _ado_get(url, access_token_id)
    if resp["response_status_code"] != 200 or resp["response_type"] != "json":
        logger.error(
            f"AzDevOps security namespaces fetch failed org={org}. "
            f"Status {resp['response_status_code']}"
        )
        return (
            f"[Error] Failed to list security namespaces. Status {resp['response_status_code']}.",
            400,
        )
    body = json.loads(resp["response_text"])
    namespaces = body.get("value", [])
    logger.debug(f"AzDevOps: retrieved {len(namespaces)} security namespace(s) for org={org}")
    return namespaces
