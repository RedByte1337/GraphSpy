# graphspy/cli.py

# Built-in imports
import argparse
import os
from pathlib import Path

# Local library imports
from . import __version__, banner
from .app import create_app
from .db import connection, migrations, schema
from .utils import logbook

# Third party library imports
from loguru import logger


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

    advanced_group = parser.add_argument_group(
        "Advanced Options", "Additional advanced or debugging options."
    )

    advanced_group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging (shortcut for --log-level DEBUG).",
    )

    advanced_group.add_argument(
        "--trace",
        action="store_true",
        help="Enable TRACE logging (shortcut for --log-level TRACE).",
    )

    advanced_group.add_argument(
        "--log-level",
        type=str,
        choices=["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=None,
        help="Set the logging level explicitly.",
    )

    advanced_group.add_argument(
        "--dev",
        action="store_true",
        help="Run with Flask development server (auto-reload, debugger). Do not use in production.",
    )

    return parser


def get_app_dir() -> Path:
    """Return the data directory, preferring XDG/platform paths, falling back to legacy ~/.gspy/."""
    # New XDG-compliant / platform-appropriate path
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", str(Path.home())))
    else:
        base = Path(
            os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))
        )
    xdg_dir = (base / "graphspy").resolve()
    if xdg_dir.is_dir():
        return xdg_dir

    # Fall back to legacy path used by older versions
    legacy_dir = Path.home() / ".gspy"
    if legacy_dir.is_dir():
        return legacy_dir

    # Neither exists yet — use the new XDG path
    return xdg_dir


def resolve_paths(database: str) -> tuple[Path, Path]:
    """Resolve and create required directories, return (db_folder, db_path)."""
    data_dir = get_app_dir()
    db_folder = data_dir / "databases"

    for directory in (data_dir, db_folder):
        if not directory.exists():
            logger.info(f"Creating directory '{directory}'.")
            directory.mkdir(parents=True, exist_ok=True)
            if not directory.exists():
                raise OSError(f"Failed creating directory '{directory}'.")

    db_name = database if database.endswith(".db") else f"{database}.db"
    db_path = connection.safe_join(str(db_folder), db_name)
    if not db_path:
        raise ValueError(f"Invalid database name '{db_name}'.")

    return db_folder, Path(db_path)


def main() -> int:
    # Only show banner in the main process, not the reloader child
    if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        print(banner.display_banner())

    parser = build_parser()
    args = parser.parse_args()

    # Determine log level: --log-level takes precedence, then --debug, then --trace, then default INFO
    if args.log_level:
        log_level = args.log_level
    elif args.debug:
        log_level = "DEBUG"
    elif args.trace:
        log_level = "TRACE"
    else:
        log_level = "INFO"

    data_dir = get_app_dir()
    log_dir = data_dir / "logs"
    logbook.setup_logging(level=log_level, log_dir=log_dir)

    is_reloader = os.environ.get("WERKZEUG_RUN_MAIN") == "true"

    try:
        db_folder, db_path = resolve_paths(args.database)
    except (OSError, ValueError) as exc:
        logger.error(str(exc))
        return 1

    if not db_path.exists():
        if not is_reloader:
            logger.info(f"Database '{db_path}' not found. Initializing new database.")
        schema.init_db(str(db_path))
        if not db_path.exists():
            logger.error(
                "Failed creating database file at '{}'. Unable to proceed.", db_path
            )
            return 1

    if not is_reloader:
        logger.info(f"Utilizing database '{db_path}'.")

    app = create_app(db_path=str(db_path), db_folder=str(db_folder))

    with app.app_context():
        migrations.update_db()

    if not is_reloader:
        logger.info(
            "Starting GraphSpy. Open in your browser by going to the url displayed below.\n"
        )

    if args.dev:
        logger.warning("Running in development mode. Do not use in production.")
        app.run(debug=True, host=args.interface, port=args.port)
    else:
        # Avoid using Flask's built-in server in production.
        from waitress import serve

        serve(app, host=args.interface, port=args.port)
    return 0
