# graphspy/web/pages.py

# External library imports
from flask import Blueprint, render_template

bp = Blueprint("pages", __name__)

@bp.get("/")
def settings():
    return render_template("settings.html", title="Settings")


@bp.get("/access_tokens")
def access_tokens():
    return render_template("access_tokens.html", title="Access Tokens")


@bp.get("/refresh_tokens")
def refresh_tokens():
    return render_template("refresh_tokens.html", title="Refresh Tokens")


@bp.get("/device_certificates")
def device_certificates():
    return render_template("device_certificates.html", title="Device Certificates")


@bp.get("/primary_refresh_tokens")
def primary_refresh_tokens():
    return render_template(
        "primary_refresh_tokens.html", title="Primary Refresh Tokens"
    )


@bp.get("/winhello_keys")
def winhello_keys():
    return render_template("winhello_keys.html", title="Windows Hello Keys")


@bp.get("/device_codes")
def device_codes():
    return render_template("device_codes.html", title="Device Codes")


@bp.get("/mfa")
def mfa():
    return render_template("mfa.html", title="MFA Methods")


@bp.get("/custom_requests")
def custom_requests():
    return render_template("custom_requests.html", title="Custom Requests")


@bp.get("/generic_search")
def generic_search():
    return render_template("generic_search.html", title="Generic MSGraph Search")


@bp.get("/recent_files")
def recent_files():
    return render_template("recent_files.html", title="Recent Files")


@bp.get("/shared_with_me")
def shared_with_me():
    return render_template("shared_with_me.html", title="Files Shared With Me")


@bp.get("/onedrive")
def onedrive():
    return render_template("OneDrive.html", title="OneDrive")


@bp.get("/sharepoint_sites")
def sharepoint_sites():
    return render_template("SharePointSites.html", title="SharePoint Sites")


@bp.get("/sharepoint_drives")
def sharepoint_drives():
    return render_template("SharePointDrives.html", title="SharePoint Drives")


@bp.get("/sharepoint")
def sharepoint():
    return render_template("SharePoint.html", title="SharePoint")


@bp.get("/outlook")
def outlook():
    return render_template("outlook.html", title="Outlook")


@bp.get("/outlook_graph")
def outlook_graph():
    return render_template("outlook_graph.html", title="Outlook Graph")


@bp.get("/teams")
def teams():
    return render_template("teams.html", title="Microsoft Teams")


@bp.get("/entra_users")
def entra_users():
    return render_template("entra_users.html", title="Entra ID Users")
