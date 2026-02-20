# graphspy/api/database.py

# Built-in imports
import os
import shutil

# External library imports
from flask import Blueprint, current_app, request

# Local library imports
from ..db import connection, migrations, schema, utils

bp = Blueprint("database", __name__)


@bp.get("/api/list_databases")
def list_databases():
    return utils.list_databases()


@bp.post("/api/create_database")
def create_database():
    database_name = request.form.get("database", "")
    if not database_name:
        return "[Error] Please specify a database name."
    database_name = (
        database_name if database_name.endswith(".db") else f"{database_name}.db"
    )
    db_path = connection.safe_join(
        current_app.config["graph_spy_db_folder"], database_name
    )
    if not db_path:
        return f"[Error] Invalid database name '{database_name}'."
    if os.path.exists(db_path):
        return f"[Error] Database '{database_name}' already exists."
    old_db = current_app.config["graph_spy_db_path"]
    current_app.config["graph_spy_db_path"] = db_path
    schema.init_db(db_path)
    if not os.path.exists(db_path):
        current_app.config["graph_spy_db_path"] = old_db
        return f"[Error] Failed to create database '{database_name}'."
    return f"[Success] Created and activated '{database_name}'."


@bp.post("/api/activate_database")
def activate_database():
    database_name = request.form.get("database", "")
    db_path = connection.safe_join(
        current_app.config["graph_spy_db_folder"], database_name
    )
    if not os.path.exists(db_path):
        return f"[Error] Database file '{db_path}' not found."
    current_app.config["graph_spy_db_path"] = db_path
    migrations.update_db()
    return f"[Success] Activated database '{database_name}'."


@bp.post("/api/duplicate_database")
def duplicate_database():
    database_name = request.form.get("database", "")
    db_path = connection.safe_join(
        current_app.config["graph_spy_db_folder"], database_name
    )
    if not os.path.exists(db_path):
        return f"[Error] Database file '{db_path}' not found."
    for i in range(1, 100):
        new_path = f"{db_path.rstrip('.db')}_{i}.db"
        if not os.path.exists(new_path):
            shutil.copy2(db_path, new_path)
            return f"[Success] Duplicated '{database_name}' to '{os.path.basename(new_path)}'."
    return f"[Error] Could not duplicate database '{database_name}'."


@bp.post("/api/delete_database")
def delete_database():
    database_name = request.form.get("database", "")
    db_path = connection.safe_join(
        current_app.config["graph_spy_db_folder"], database_name
    )
    if current_app.config["graph_spy_db_path"].lower() == db_path.lower():
        return "[Error] Can't delete the active database."
    os.remove(db_path)
    if not os.path.exists(db_path):
        return f"[Success] Database '{database_name}' deleted."
    return f"[Error] Failed to delete '{database_name}'."
