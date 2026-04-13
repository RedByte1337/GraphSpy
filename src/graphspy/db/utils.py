# graphspy/db/utils.py

# Built-in imports
import os
from datetime import datetime

# External library imports
from flask import current_app


def list_databases() -> list[dict]:
    db_folder = current_app.config["graph_spy_db_folder"]
    db_path = current_app.config["graph_spy_db_path"]
    return [
        {
            "name": entry.name,
            "last_modified": f"{datetime.fromtimestamp(entry.stat().st_mtime)}".split(
                "."
            )[0],
            "size": f"{round(entry.stat().st_size / 1024)} KB",
            "state": (
                "Active"
                if entry.name.lower() == os.path.basename(db_path).lower()
                else "Inactive"
            ),
        }
        for entry in os.scandir(db_folder)
        if entry.is_file() and entry.name.endswith(".db")
    ]
