import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Central application configuration for the SecureVision platform."""

    SECRET_KEY = os.environ.get("SECRET_KEY", "securevision-vapt-demo")
    DB_PATH = Path(os.environ.get("SECUREVISION_DB_PATH", BASE_DIR / "database" / "database.db"))
