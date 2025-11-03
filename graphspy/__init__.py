from importlib.metadata import version, PackageNotFoundError
from pathlib import Path
import tomllib

try:
    __version__ = version("graphspy")
except PackageNotFoundError:
    # Fallback: read directly from pyproject.toml for development
    try:
        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        with open(pyproject_path, "rb") as f:
            pyproject_data = tomllib.load(f)
            __version__ = pyproject_data["project"]["version"] + "-dev"
    except (FileNotFoundError, KeyError):
        __version__ = "unknown"

__all__ = ["__version__"]