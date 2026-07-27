from pathlib import Path

from flask import Flask

from api.dashboard import dashboard_bp
from api.devices import devices_bp
from api.reports import reports_bp
from api.scan import scan_bp
from api.assets import assets_bp
from api.export import export_bp
from api.remediation import remediation_bp
from api.alerts import alerts_bp
from api.integration import integration_bp
from core.config import Config
from database.db import init_db
from utils.logger import setup_logging


def create_app() -> Flask:
    """Create and configure the Flask application instance."""

    base_dir = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        template_folder=str(base_dir / "templates"),
        static_folder=str(base_dir / "static"),
    )
    app.config.from_object(Config)

    setup_logging()
    init_db()

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(export_bp)
    app.register_blueprint(remediation_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(integration_bp)

    return app
