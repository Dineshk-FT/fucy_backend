from flask import Flask
from flask_pymongo import PyMongo
import logging
from logging.handlers import RotatingFileHandler
import os
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

mongo = PyMongo()


def create_app():
    # app = Flask(__name__)
    # app.config.from_object('config.Config')

    # mongo.init_app(app)

    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Set up logging to file
    log_file = os.path.join(log_dir, "info.log")
    handler = RotatingFileHandler(log_file, maxBytes=10000, backupCount=3)
    handler.setLevel(logging.INFO)
    handler.setFormatter(
        logging.Formatter(
            "[%(asctime)s] {%(pathname)s:%(funcName)s %(lineno)d} %(levelname)s - %(message)s"
        )
    )

    # Set up error logging to file
    error_file = os.path.join(log_dir, "error.log")
    error_handler = RotatingFileHandler(error_file, maxBytes=10000, backupCount=3)
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
        )
    )

    # Add handlers to the app's logger
    app.logger.addHandler(handler)
    app.logger.addHandler(error_handler)

    # Set the logging level for the app's logger
    app.logger.setLevel(logging.INFO)

    # Log unhandled exceptions
    @app.errorhandler(Exception)
    def log_exception(e):
        app.logger.error("Unhandled Exception: %s", e, exc_info=True)
        return "Internal Server Error", 500

    # with app.app_context():
    #     from . import routes,auth

    from app.auth import app as auth

    app.register_blueprint(auth)

    from app.routes import app as routes

    app.register_blueprint(routes)

    from app.v1.hello import app as hello

    app.register_blueprint(hello)

    from app.v1.DamageScenarios import app as dmg_scr

    app.register_blueprint(dmg_scr)

    from app.v1.Models import app as models

    app.register_blueprint(models)

    from app.v1.Assets import app as assets

    app.register_blueprint(assets)

    from app.v1.ThreatScenarios import app as treath_scr

    app.register_blueprint(treath_scr)

    from app.v1.Attacks import app as attacks

    app.register_blueprint(attacks)

    from app.v1.CyberSecurity import app as cybersecurity

    app.register_blueprint(cybersecurity)

    from app.v1.RiskDeterminationAndTreatment import app as riskDetAndTreat

    app.register_blueprint(riskDetAndTreat)

    from app.v1.Doc import app as doc

    app.register_blueprint(doc)

    from app.v1.ProcessPrompt import app as prompt

    app.register_blueprint(prompt)

    from app.v1.importExport import app as impexp
    
    app.register_blueprint(impexp)

    return app
