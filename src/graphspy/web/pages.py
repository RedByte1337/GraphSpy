# graphspy/web/pages.py

# Built-in imports
import os

# External library imports
from flask import render_template, send_from_directory


def register(app) -> None:
    @app.route("/favicon.ico")
    def favicon():
        return send_from_directory(
            os.path.join(app.root_path, "web", "static"),
            "favicon.ico",
            mimetype="image/vnd.microsoft.icon",
        )

    @app.route("/")
    def settings():
        return render_template("settings.html", title="Settings")

    @app.route("/access_tokens")
    def access_tokens():
        return render_template("access_tokens.html", title="Access Tokens")

    @app.route("/refresh_tokens")
    def refresh_tokens():
        return render_template("refresh_tokens.html", title="Refresh Tokens")

    @app.route("/device_certificates")
    def device_certificates():
        return render_template("device_certificates.html", title="Device Certificates")

    @app.route("/primary_refresh_tokens")
    def primary_refresh_tokens():
        return render_template("primary_refresh_tokens.html", title="Primary Refresh Tokens")

    @app.route("/winhello_keys")
    def winhello_keys():
        return render_template("winhello_keys.html", title="Windows Hello Keys")

    @app.route("/device_codes")
    def device_codes():
        return render_template("device_codes.html", title="Device Codes")

    @app.route("/mfa")
    def mfa():
        return render_template("mfa.html", title="MFA Methods")

    @app.route("/custom_requests")
    def custom_requests():
        return render_template("custom_requests.html", title="Custom Requests")

    @app.route("/generic_search")
    def generic_search():
        return render_template("generic_search.html", title="Generic MSGraph Search")

    @app.route("/recent_files")
    def recent_files():
        return render_template("recent_files.html", title="Recent Files")

    @app.route("/shared_with_me")
    def shared_with_me():
        return render_template("shared_with_me.html", title="Files Shared With Me")

    @app.route("/onedrive")
    def onedrive():
        return render_template("OneDrive.html", title="OneDrive")

    @app.route("/sharepoint_sites")
    def sharepoint_sites():
        return render_template("SharePointSites.html", title="SharePoint Sites")

    @app.route("/sharepoint_drives")
    def sharepoint_drives():
        return render_template("SharePointDrives.html", title="SharePoint Drives")

    @app.route("/sharepoint")
    def sharepoint():
        return render_template("SharePoint.html", title="SharePoint")

    @app.route("/outlook")
    def outlook():
        return render_template("outlook.html", title="Outlook")

    @app.route("/outlook_graph")
    def outlook_graph():
        return render_template("outlook_graph.html", title="Outlook Graph")

    @app.route("/teams")
    def teams():
        return render_template("teams.html", title="Microsoft Teams")

    @app.route("/entra_users")
    def entra_users():
        return render_template("entra_users.html", title="Entra ID Users")