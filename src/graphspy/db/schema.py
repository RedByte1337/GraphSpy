# graphspy/db/schema.py

# Built-in imports
import sqlite3


def init_db(db_path: str) -> None:
    con = sqlite3.connect(db_path)
    con.execute(
        "CREATE TABLE accesstokens (id INTEGER PRIMARY KEY AUTOINCREMENT, stored_at TEXT, issued_at TEXT, expires_at TEXT, description TEXT, user TEXT, resource TEXT, accesstoken TEXT)"
    )
    con.execute(
        "CREATE TABLE refreshtokens (id INTEGER PRIMARY KEY AUTOINCREMENT, stored_at TEXT, description TEXT, user TEXT, tenant_id TEXT, client_id TEXT, resource TEXT, foci INTEGER, refreshtoken TEXT)"
    )
    con.execute(
        "CREATE TABLE devicecodes (id INTEGER PRIMARY KEY AUTOINCREMENT, generated_at INTEGER, expires_at INTEGER, user_code TEXT, device_code TEXT, interval INTEGER, client_id TEXT, status TEXT"
        + ", last_poll INTEGER, auto_action TEXT, auto_device_name TEXT, auto_join_type INTEGER, auto_device_type TEXT, auto_os_version TEXT, auto_target_domain TEXT)"
    )
    con.execute(
        "CREATE TABLE request_templates (id INTEGER PRIMARY KEY AUTOINCREMENT, template_name TEXT, uri TEXT, method TEXT, request_type TEXT, body TEXT, headers TEXT, variables TEXT)"
    )
    con.execute(
        "CREATE TABLE teams_settings (access_token_id INTEGER PRIMARY KEY, skypeToken TEXT, skype_id TEXT, issued_at INTEGER, expires_at INTEGER, teams_settings_raw TEXT)"
    )
    con.execute(
        "CREATE TABLE mfa_otp (id INTEGER PRIMARY KEY AUTOINCREMENT, stored_at TEXT, secret_key TEXT, account_name INTEGER, description TEXT)"
    )
    con.execute(
        "CREATE TABLE device_certificates (id INTEGER PRIMARY KEY AUTOINCREMENT, stored_at INTEGER, device_id TEXT, device_name TEXT, device_type TEXT, join_type TEXT, priv_key TEXT, certificate TEXT)"
    )
    con.execute(
        "CREATE TABLE primary_refresh_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, user TEXT, prt TEXT, session_key TEXT, issued_at INTEGER, expires_at INTEGER, description TEXT)"
    )
    con.execute(
        "CREATE TABLE winhello_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, stored_at INTEGER, key_id TEXT, device_id TEXT, user TEXT, priv_key TEXT)"
    )
    con.execute("CREATE TABLE settings (setting TEXT UNIQUE, value TEXT)")
    con.execute("INSERT INTO settings (setting, value) VALUES ('schema_version', '6')")
    con.commit()
    con.close()
