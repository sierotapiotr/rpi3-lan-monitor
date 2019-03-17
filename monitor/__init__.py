from flask import Flask
from flask_login import LoginManager
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
login = LoginManager(app)

from monitor import routes, models

