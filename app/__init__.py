from flask import Flask

from config import config
from app.exts import db
from app.hms_api import hms_api


def create_app(config_name):
    app = Flask(__name__)
    # app_config = config[config_name]
    # app.config.from_object(app_config)
    #
    # db.init_app(app)
    app.register_blueprint(hms_api)
    return app
