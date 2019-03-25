from flask import Flask
from flask_login import LoginManager
from flask_bootstrap import Bootstrap
from config_dev import Config
import logging

app = Flask(__name__)
app.config.from_object(Config)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

Bootstrap(app)

logging.basicConfig(filename='logs/monitor_log.log', level=logging.INFO, format='%(asctime)s %(message)s')

from monitor import routes
