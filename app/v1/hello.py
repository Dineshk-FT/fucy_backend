from flask import Flask
from app import app
# from flask import current_app as app
from flask import Blueprint

app = Blueprint('hello',__name__)

@app.route('/v1/hello', methods=['GET'])
def hello():
    return "Routes Working Successfully"