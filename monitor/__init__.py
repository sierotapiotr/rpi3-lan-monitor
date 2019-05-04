from flask import Flask
from flask_login import LoginManager
from flask_bootstrap import Bootstrap
from configparser import ConfigParser, ExtendedInterpolation
import logging

app = Flask(__name__)

config = ConfigParser(interpolation=ExtendedInterpolation())
config.read('config/config_dev.ini')
app.config['SECRET_KEY'] = config['general']['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = config['sqlalchemy']['SQLALCHEMY_URI_MONITOR']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = bool(int(config['sqlalchemy']['SQLALCHEMY_TRACK_MODIFICATIONS']))
app.config['TEMPLATES_AUTO_RELOAD'] = bool(int(config['general']['TEMPLATES_AUTO_RELOAD']))

logging.info(app.config['SQLALCHEMY_TRACK_MODIFICATIONS'])
logging.info(app.config['TEMPLATES_AUTO_RELOAD'])

login_manager = LoginManager(app)
login_manager.login_view = 'login'

Bootstrap(app)

logging.basicConfig(filename='logs/monitor_log.log', level=logging.INFO, format='%(asctime)s %(message)s')

from monitor import routes
