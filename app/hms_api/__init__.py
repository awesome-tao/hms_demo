from flask import Blueprint


hms_api = Blueprint('hms_api', __name__, url_prefix='/hms')

from app.hms_api import view
