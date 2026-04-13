# graphspy/core/user_agent.py

# Local library imports
from ..db import connection

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0"


def get() -> str:
    row = connection.query_db(
        "SELECT value FROM settings WHERE setting = 'user_agent'", one=True
    )
    return row[0] if row else DEFAULT_USER_AGENT


def set(user_agent: str) -> bool:
    connection.execute_db(
        "INSERT OR REPLACE INTO settings (setting, value) VALUES ('user_agent', ?)",
        (user_agent,),
    )
    return get() == user_agent
