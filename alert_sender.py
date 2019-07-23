import logging
import os

from configparser import ConfigParser
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from database.database import CrackedPassword, DetectedHost, OpenPort
from monitor_utils.db_utils import sqlalchemy_tuples_to_list

current_file_path = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(filename=os.path.join(current_file_path, "logs", 'alert_sender.log'), level=logging.INFO,
                    format='%(asctime)s %(message)s')

config = ConfigParser()
config.read(os.path.dirname(os.path.abspath(__file__)) + '/app_config.ini')

sqlalchemy_uri = 'sqlite:///{currentFilePath}/{databaseFilePath}'.format(
    currentFilePath=current_file_path,
    databaseFilePath=config['sqlalchemy']['SQLALCHEMY_DATABASE_FILEPATH'])
engine = create_engine(sqlalchemy_uri)
session_factory = sessionmaker(bind=engine, expire_on_commit=False)
Session = scoped_session(session_factory)


def check_for_dangers():
    session = Session()

    untrusted_hosts = session.query(DetectedHost.address).filter_by(confirmed=False).all()
    suspicious_open_ports = session.query(OpenPort.port).filter_by(suspicious=True).all()
    cracked_passwords = session.query(CrackedPassword).all()

    if untrusted_hosts or suspicious_open_ports or cracked_passwords:
        detected_hosts = session.query(DetectedHost).all()
        alert_data = {'detected_hosts': detected_hosts, 'untrusted_hosts': untrusted_hosts, 'open_ports': suspicious_open_ports,
                      'cracked_passwords': cracked_passwords}
        alert_message = craft_alert_message(alert_data)
        send_alert(alert_message)
    Session.remove()
    return


def craft_alert_message(alert_data):
    alert_message = 'Wykryto następujące niezaufane hosty:\n'
    for host in alert_data['untrusted_hosts']:
        alert_message += (host.address + '\n')

    alert_message += '\nWykryto następujące otwarte porty, kojarzone z podatnymi aplikacjami:\n'
    for host in alert_data['detected_hosts']:
        for port in host.open_ports:
            if port.suspicious:
                alert_message += "{port} ({service}) na hoście {host}\n".format(host=host.address, port=port.port, service=port.service)

    alert_message += '\nWykryto słabe/domyślne hasła dla następujących loginów:\n'
    for host in alert_data['detected_hosts']:
        for password in host.cracked_passwords:
            alert_message += '{login} dla aplikacji {service} ({host}:{port})\n'.\
                format(service=password.service, port=password.port, host=host.address, login=password.login)
    return alert_message


def send_alert(alert_message):
    print(alert_message)
    return


check_for_dangers()
