from database.database import User, MonitoringSession, DetectedHost, OpenPort
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
session_factory = sessionmaker(bind=engine, expire_on_commit=False)
Session = scoped_session(session_factory)

db_session = Session()
target = db_session.query(User.target).filter_by(id=1).first()[0]
logging.info("Creating port scanner.")
nm = nmap.PortScanner()
logging.info("Starting the scanning for " + target)
nm.scan(hosts=target, arguments="-sS -O", sudo=True)
scan_results = nm.csv()
logging.info("Finished the scanning for " + target)

try:
    db_session = Session()

    monitoring_session = MonitoringSession(datetime=NOW)
    db_session.add(monitoring_session)

    network_learning = db_session.query(User.network_learning).filter_by(id=1).first()[0]

    already_detected_addresses = sqlalchemy_tuples_to_list(db_session.query(DetectedHost.mac_address).all())

    for host in nm.all_hosts():
        mac_address = nm[host]['addresses']['mac']
        manufacturer = nm[host]['vendor'][mac_address]

        if mac_address in already_detected_addresses:
            res =  db_session.query(DetectedHost).filter_by(mac_address=mac_address).all()
            db_session.query(DetectedHost).filter_by(mac_address=mac_address).update({DetectedHost.last_seen: NOW})
            db_session.commit()
        else:
            detected_host = DetectedHost(address=host, mac_address=mac_address, manufacturer=manufacturer, last_seen=NOW,
                                         confirmed=False)
            if network_learning == "active":
                detected_host.confirmed = True
            monitoring_session.detected_hosts.append(detected_host)

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
