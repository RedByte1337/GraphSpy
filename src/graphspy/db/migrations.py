# graphspy/db/migrations.py

# External library imports
from flask import current_app

# Local library imports
from .connection import execute_db, query_db


def update_db() -> None:
    db_path = current_app.config["graph_spy_db_path"]
    latest_schema_version = "6"
    current_version = query_db(
        db_path, "SELECT value FROM settings WHERE setting = 'schema_version'", one=True
    )[0]

    if current_version == "1":
        print("[*] Updating database schema version 1 -> 2")
        execute_db(
            db_path,
            "CREATE TABLE request_templates (id INTEGER PRIMARY KEY AUTOINCREMENT, template_name TEXT, uri TEXT, method TEXT, request_type TEXT, body TEXT, headers TEXT, variables TEXT)",
        )
        execute_db(
            db_path, "UPDATE settings SET value = '2' WHERE setting = 'schema_version'"
        )
        print("[*] Updated database to schema version 2")
        current_version = query_db(
            db_path,
            "SELECT value FROM settings WHERE setting = 'schema_version'",
            one=True,
        )[0]

    if current_version == "2":
        print("[*] Updating database schema version 2 -> 3")
        execute_db(
            db_path,
            "CREATE TABLE teams_settings (access_token_id INTEGER PRIMARY KEY, skypeToken TEXT, skype_id TEXT, issued_at INTEGER, expires_at INTEGER, teams_settings_raw TEXT)",
        )
        execute_db(
            db_path, "UPDATE settings SET value = '3' WHERE setting = 'schema_version'"
        )
        print("[*] Updated database to schema version 3")
        current_version = query_db(
            db_path,
            "SELECT value FROM settings WHERE setting = 'schema_version'",
            one=True,
        )[0]

    if current_version == "3":
        print("[*] Updating database schema version 3 -> 4")
        execute_db(
            db_path,
            "CREATE TABLE mfa_otp (id INTEGER PRIMARY KEY AUTOINCREMENT, stored_at TEXT, secret_key TEXT, account_name INTEGER, description TEXT)",
        )
        execute_db(
            db_path, "UPDATE settings SET value = '4' WHERE setting = 'schema_version'"
        )
        print("[*] Updated database to schema version 4")
        current_version = query_db(
            db_path,
            "SELECT value FROM settings WHERE setting = 'schema_version'",
            one=True,
        )[0]

    if current_version == "4":
        print("[*] Updating database schema version 4 -> 5")
        execute_db(
            db_path,
            "CREATE TABLE device_certificates (id INTEGER PRIMARY KEY AUTOINCREMENT, stored_at INTEGER, device_id TEXT, device_name TEXT, device_type TEXT, join_type TEXT, priv_key TEXT, certificate TEXT)",
        )
        execute_db(
            db_path,
            "CREATE TABLE primary_refresh_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, user TEXT, prt TEXT, session_key TEXT, issued_at INTEGER, expires_at INTEGER, description TEXT)",
        )
        execute_db(
            db_path,
            "CREATE TABLE winhello_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, stored_at INTEGER, key_id TEXT, device_id TEXT, user TEXT, priv_key TEXT)",
        )
        execute_db(db_path, "ALTER TABLE refreshtokens ADD COLUMN client_id TEXT")
        execute_db(
            db_path, "UPDATE settings SET value = '5' WHERE setting = 'schema_version'"
        )
        print("[*] Updated database to schema version 5")
        current_version = query_db(
            db_path,
            "SELECT value FROM settings WHERE setting = 'schema_version'",
            one=True,
        )[0]

    if current_version == "5":
        print("[*] Updating database schema version 5 -> 6")
        execute_db(db_path, "ALTER TABLE devicecodes ADD COLUMN auto_action TEXT")
        execute_db(db_path, "ALTER TABLE devicecodes ADD COLUMN auto_device_name TEXT")
        execute_db(db_path, "ALTER TABLE devicecodes ADD COLUMN auto_join_type INTEGER")
        execute_db(db_path, "ALTER TABLE devicecodes ADD COLUMN auto_device_type TEXT")
        execute_db(db_path, "ALTER TABLE devicecodes ADD COLUMN auto_os_version TEXT")
        execute_db(
            db_path, "ALTER TABLE devicecodes ADD COLUMN auto_target_domain TEXT"
        )
        execute_db(
            db_path, "UPDATE settings SET value = '6' WHERE setting = 'schema_version'"
        )
        print("[*] Updated database to schema version 6")
