from flask import Flask
from flask_login import LoginManager
from flask_bootstrap import Bootstrap
from config_dev import Config
import logging

app = Flask(__name__)
app.config.from_object(Config)
login = LoginManager(app)
login.login_view = 'login'
logging.basicConfig(filename='logs/monitor_log.log', level=logging.INFO, format='%(asctime)s %(message)s')
Bootstrap(app)

from monitor import routes, models

