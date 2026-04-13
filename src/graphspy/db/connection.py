# graphspy/db/connection.py

# Built-in imports
import os
import sqlite3

# External library imports
from flask import current_app, g


def get_db() -> sqlite3.Connection:
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(current_app.config["graph_spy_db_path"])
    return db


def close(exception) -> None:
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def query_db(query: str, args: tuple = (), one: bool = False):
    con = get_db()
    con.row_factory = sqlite3.Row
    cur = con.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def query_db_json(query: str, args: tuple = (), one: bool = False):
    con = get_db()
    con.row_factory = make_dicts
    cur = con.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def execute_db(statement: str, args: tuple = ()) -> int:
    con = get_db()
    cur = con.cursor()
    cur.execute(statement, args)
    con.commit()
    return cur.lastrowid


def make_dicts(cursor: sqlite3.Cursor, row: sqlite3.Row) -> dict:
    return dict((cursor.description[idx][0], value) for idx, value in enumerate(row))


def safe_join(directory: str, filename: str) -> str | None:
    os_seps = [sep for sep in [os.path.sep, os.path.altsep] if sep is not None]
    filename = os.path.normpath(filename)
    for sep in os_seps:
        if sep in filename:
            return None
    if os.path.isabs(filename) or filename.startswith("../"):
        return None
    if not os.path.normpath(os.path.join(directory, filename)).startswith(directory):
        return None
    return os.path.join(directory, filename)
