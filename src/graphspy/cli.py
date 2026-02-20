# graphspy/cli.py

# Built-in imports
import argparse
import os
import sys

# Local library imports
from . import __version__, banner
from .app import create_app
from .db import connection, migrations, schema


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="graphspy",
        description="Launches the GraphSpy Flask application",
        epilog="For more information, see https://github.com/RedByte1337/GraphSpy",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default="127.0.0.1",
        help="Interface to bind to. Use 0.0.0.0 for all. (Default: 127.0.0.1)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=5000,
        help="Port to bind to. (Default: 5000)",
    )
    parser.add_argument(
        "-d",
        "--database",
        type=str,
        default="database.db",
        help="Database file to utilize. (Default: database.db)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable Flask debug mode.",
    )
    return parser


def get_data_dir() -> str:
    """Return the platform-appropriate data directory following XDG on Linux/Mac."""
    if os.name == "nt":
        # Windows: use %APPDATA%\graphspy
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
    else:
        # Linux/Mac: XDG_DATA_HOME defaults to ~/.local/share
        base = os.environ.get("XDG_DATA_HOME", os.path.join(os.path.expanduser("~"), ".local", "share"))
    return os.path.normpath(os.path.join(base, "graphspy"))


def resolve_paths(database: str) -> tuple[str, str]:
    """Resolve and create required directories, return (db_folder, db_path)."""
    data_dir = get_data_dir()
    db_folder = os.path.join(data_dir, "databases")

    for directory in (data_dir, db_folder):
        if not os.path.exists(directory):
            print(f"[*] Creating directory '{directory}'.")
            os.makedirs(directory, exist_ok=True)
            if not os.path.exists(directory):
                sys.exit(f"Failed creating directory '{directory}'. Unable to proceed.")

    db_name = database if database.endswith(".db") else f"{database}.db"
    db_path = connection.safe_join(db_folder, db_name)
    if not db_path:
        sys.exit(f"Invalid database name '{db_name}'.")

    return db_folder, db_path


def main():
    print(banner.display_banner())

    args = build_parser().parse_args()
    db_folder, db_path = resolve_paths(args.database)

    if not os.path.exists(db_path):
        print(f"[*] Database '{db_path}' not found. Initializing new database.")
        schema.init_db(db_path)

    print(f"[*] Utilizing database '{db_path}'.")

    app = create_app(db_path=db_path, db_folder=db_folder, debug=args.debug)

    with app.app_context():
        migrations.update_db()

    print("[*] Starting GraphSpy. Open in your browser at the URL displayed below.\n")
    app.run(debug=args.debug, host=args.interface, port=args.port)
