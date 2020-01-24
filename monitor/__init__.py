import logging
import os

from configparser import ConfigParser
from flask import Flask
from flask_login import LoginManager
from flask_bootstrap import Bootstrap

app = Flask(__name__)

current_file_path = os.path.dirname(os.path.abspath(__file__))

config = ConfigParser()
config.read(current_file_path + '/../app_config.ini')
app.config['SECRET_KEY'] = config['general']['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = config['sqlalchemy']['SQLALCHEMY_DATABASE_URI']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = bool(int(config['sqlalchemy']['SQLALCHEMY_TRACK_MODIFICATIONS']))
app.config['TEMPLATES_AUTO_RELOAD'] = bool(int(config['general']['TEMPLATES_AUTO_RELOAD']))

login_manager = LoginManager(app)
login_manager.login_view = 'login'

Bootstrap(app)

logging.basicConfig(filename='logs/monitor_log.log', level=logging.INFO, format='%(asctime)s %(message)s')

import monitor.login
import monitor.network_state
import monitor.settings
