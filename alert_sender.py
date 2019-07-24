import logging
import os
import smtplib

from configparser import ConfigParser
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from database.database import CrackedPassword, DetectedHost, OpenPort, User

current_file_path = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(filename=os.path.join(current_file_path, "logs", 'alert_sender.log'), level=logging.INFO,
                    format='%(asctime)s %(message)s')

config = ConfigParser()
config.read(os.path.dirname(os.path.abspath(__file__)) + '/app_config.ini')

mail_config = ConfigParser()
mail_config.read(os.path.dirname(os.path.abspath(__file__)) + '/monitor/secret/mail_config.ini')

sqlalchemy_uri = 'sqlite:///{currentFilePath}/{databaseFilePath}'.format(
    currentFilePath=current_file_path,
    databaseFilePath=config['sqlalchemy']['SQLALCHEMY_DATABASE_FILEPATH'])
engine = create_engine(sqlalchemy_uri)
session_factory = sessionmaker(bind=engine, expire_on_commit=False)
Session = scoped_session(session_factory)


def check_for_dangers():
    session = Session()

    untrusted_hosts = session.query(DetectedHost.address).filter_by(confirmed=False, notified=False).all()
    suspicious_open_ports = session.query(OpenPort.port).filter_by(suspicious=True, notified=False).all()
    cracked_passwords = session.query(CrackedPassword).filter_by(notified=False).all()

    if untrusted_hosts or suspicious_open_ports or cracked_passwords:
        logging.info('Dangers found. Preparing to send alert...')
        detected_hosts = session.query(DetectedHost).all()
        alert_data = {'detected_hosts': detected_hosts, 'untrusted_hosts': untrusted_hosts,
                      'open_ports': suspicious_open_ports, 'cracked_passwords': cracked_passwords}
        alert_message = craft_alert_message(alert_data)
        send_alert(session, alert_message)

        session.query(DetectedHost).filter_by(confirmed=False, notified=False).update({DetectedHost.notified: True})
        session.query(OpenPort).filter_by(suspicious=True, notified=False).update({OpenPort.notified: True})
        session.query(CrackedPassword).filter_by(notified=False).update({CrackedPassword.notified: True})
        session.commit()
    Session.remove()
    return


def craft_alert_message(alert_data):
    logging.info('Crafting alert message...')
    alert_message = ''
    if alert_data['untrusted_hosts']:
        alert_message += 'Wykryto następujące niezaufane hosty:\n'
        for host in alert_data['untrusted_hosts']:
            alert_message += (' - {host}\n'.format(host=host.address))

    alert_message += '\nWykryto następujące otwarte porty, kojarzone z podatnymi aplikacjami:\n'
    for host in alert_data['detected_hosts']:
        for port in host.open_ports:
            if port.suspicious and not port.notified:
                alert_message += " - {port} ({service}) na hoście {host}\n".format(host=host.address, port=port.port,
                                                                                   service=port.service)

    for host in alert_data['detected_hosts']:
        for password in host.cracked_passwords:
            if not password.notified:
                alert_message += ' - {login} dla aplikacji {service} ({host}:{port})\n'.\
                    format(service=password.service, port=password.port, host=host.address, login=password.login)
    logging.info('Crafted alert message.')
    return alert_message


def send_alert(session, alert_message):
    receiver = session.query(User).filter_by(id=1).first()

    email_user = mail_config['mailserver']['user']
    email_password = mail_config['mailserver']['password']

    subject = 'ALERT: Raspberry Pi LAN Monitor'
    msg = MIMEMultipart()
    msg['From'] = email_user
    msg['Subject'] = subject

    msg.attach(MIMEText(alert_message, 'plain'))

    server = smtplib.SMTP(mail_config['mailserver']['smtp_server'], int(mail_config['mailserver']['smtp_port']))
    server.starttls()
    server.login(email_user, email_password)

    msg['To'] = receiver.email
    text = msg.as_string()
    server.sendmail(email_user, receiver.email, text)
    logging.info('Email has been sent.')

    server.quit()
    return
