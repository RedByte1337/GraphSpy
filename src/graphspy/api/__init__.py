# graphspy/api/__init__.py

# Local library imports
from . import (
    access_tokens,
    database,
    device_codes,
    devices,
    entra,
    mfa,
    requests_,
    refresh_tokens,
    settings,
    teams,
)


def register_blueprints(app) -> None:
    for module in (
        access_tokens,
        database,
        device_codes,
        devices,
        entra,
        mfa,
        requests_,
        refresh_tokens,
        settings,
        teams,
    ):
        app.register_blueprint(module.bp)
