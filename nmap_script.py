from database.database import User, MonitoringSession, DetectedHost, TrustedHost, OpenPort
from database.suspicious_ports_services import SUSPICIOUS_PORTS, SUSPICIOUS_SERVICES
from arp_script import get_mac_address
from monitor_utils.db_utils import sqlalchemy_tuples_to_list
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from configparser import ConfigParser

import nmap
import logging
import datetime
import os

NOW = datetime.datetime.now()

current_file_path = os.path.dirname(os.path.abspath(__file__))

PATH_LOGS = current_file_path + "/logs/"
PATH_OUTPUT = current_file_path + "/output/nmap"

logging.basicConfig(filename=PATH_LOGS + 'nmap_log.log', level=logging.INFO, format='%(asctime)s %(message)s')

config = ConfigParser()
config.read(os.path.dirname(os.path.abspath(__file__)) + '/app_config.ini')

sqlalchemy_uri = 'sqlite:///{currentFilePath}/{databaseFilePath}'.format(
    currentFilePath=current_file_path,
    databaseFilePath=config['sqlalchemy']['SQLALCHEMY_DATABASE_FILEPATH'])
engine = create_engine(sqlalchemy_uri)
session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)

db_session = Session()
target = db_session.query(User.target).filter_by(id=1).first()[0]
logging.info("Creating port scanner.")
nm = nmap.PortScanner()
logging.info("Starting the scanning for " + target)
nm.scan(hosts=target, arguments="-sS", sudo=True)
logging.info("Finished the scanning for " + target)

try:
    db_session = Session()
    network_learning = db_session.query(User.network_learning).filter_by(id=1).first()[0]
    logging.info("Network learning: " + network_learning)
    trusted_hosts = []

    if network_learning == "active":
        trusted_hosts = db_session.query(TrustedHost.mac_address).all()
        trusted_hosts = sqlalchemy_tuples_to_list(trusted_hosts)
        logging.info("Pre-trusted hosts: " + str(trusted_hosts))
    else:
        trusted_hosts = db_session.query(TrustedHost.mac_address).filter_by(confirmed=True).all()
        trusted_hosts = sqlalchemy_tuples_to_list(trusted_hosts)
        logging.info("Pre-trusted hosts: " + str(trusted_hosts))

    monitoring_session = MonitoringSession(datetime=NOW)
    db_session.add(monitoring_session)
    logging.info("Monitoring session added.")

    for host in nm.all_hosts():
        logging.info("Getting mac address...")
        mac_address = get_mac_address(host)
        detected_host = DetectedHost(address=host, mac_address=mac_address)
        if network_learning == "active" and mac_address not in trusted_hosts:
            trusted_host = TrustedHost(mac_address=mac_address)
            db_session.add(trusted_host)
            logging.info("Added {mac_address} to trusted hosts.".format(mac_address=mac_address))
        monitoring_session.detected_hosts.append(detected_host)
        logging.info("Appended host: {host} with MAC address: {mac_address}".format(host=host, mac_address=mac_address))

        for l3_protocol in nm[host].all_protocols():
            ports = list(nm[host][l3_protocol].keys())
            for port in ports:
                open_port = OpenPort(l3_protocol=l3_protocol, port=port)
                service = nm[host][l3_protocol][port]['name']
                if port in SUSPICIOUS_PORTS or service in SUSPICIOUS_SERVICES:
                    detected_host.open_ports.append(open_port)
                    logging.info("Appended port: " + str(port))

    db_session.commit()
    logging.info("New monitoring session committed to the database.")
except Exception as e:
    logging.info(str(type(e)) + str(e))
finally:
    Session.remove()
