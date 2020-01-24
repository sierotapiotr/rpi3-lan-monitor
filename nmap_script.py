import sys

sys.path.append('/home/piotr/.local/lib/python3.6/site-packages')

from database.database import User, DetectedHost, OpenPort
from database.suspicious_ports_services import SUSPICIOUS_PORTS, SUSPICIOUS_SERVICES
from monitor_utils.db_utils import sqlalchemy_tuples_to_list
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from configparser import ConfigParser

import nmap
import logging
import datetime
import os
import socket

NOW = datetime.datetime.now()

current_file_path = os.path.dirname(os.path.abspath(__file__))

PATH_LOGS = current_file_path + "/logs/"
PATH_OUTPUT = current_file_path + "/output/nmap"

logging.basicConfig(filename=PATH_LOGS + 'nmap.log', level=logging.INFO, format='%(asctime)s %(message)s')
config = ConfigParser()
config.read(os.path.dirname(os.path.abspath(__file__)) + '/app_config.ini')

sqlalchemy_uri = 'sqlite:///{currentFilePath}/{databaseFilePath}'.format(
    currentFilePath=current_file_path,
    databaseFilePath=config['sqlalchemy']['SQLALCHEMY_DATABASE_FILEPATH'])
engine = create_engine(sqlalchemy_uri)
session_factory = sessionmaker(bind=engine, expire_on_commit=False)
Session = scoped_session(session_factory)

db_session = Session()

if not db_session.query(User.monitoring_activated).filter_by(id=1).first()[0]:
    logging.info('Monitoring not active, quitting.')
    sys.exit()

if len(sys.argv) == 1:
    target = db_session.query(User.target).filter_by(id=1).first()[0]
else:
    target = sys.argv[1]

logging.info('Setting ' + target + ' as target.')
logging.info("Creating port scanner.")
nm = nmap.PortScanner()
logging.info("Starting the scanning for " + target)
nm.scan(hosts=target, arguments="-sS", sudo=True)
scan_results = nm.csv()
logging.info("Finished the scanning for " + target)

try:
    network_learning = db_session.query(User.network_learning).filter_by(id=1).first()[0]
    already_detected_mac_addresses = sqlalchemy_tuples_to_list(db_session.query(DetectedHost.mac_address).all())
    already_detected_ip_addresses = sqlalchemy_tuples_to_list(db_session.query(DetectedHost.address).all())
    localhost_ip_addr = (([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")]
                          or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close())
                               for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]])
                         + ["no IP found"])[0]

    for host in nm.all_hosts():
        logging.info('Detected host: ' + str(host))
        if host == localhost_ip_addr:
            # logging.info('Omitting localhost: ' + str(localhost_ip_addr))
            # continue
            #  DEV PURPOSES ONLY:
            if db_session.query(DetectedHost).filter_by(address=host).first():
                current_host = db_session.query(DetectedHost).filter_by(address=host).first()
                db_session.query(DetectedHost).filter_by(address=host).update({DetectedHost.last_seen: NOW})
                logging.info('Present host: ' + str(host))
            else:
                current_host = DetectedHost(address=host, confirmed=False, last_seen=NOW, mac_address='localhost',
                                            manufacturer='localhost', notified=False)
                db_session.add(current_host)
                logging.info('New host: ' + str(host))
            db_session.commit()
        else:
            #  END OF DEV PURPOSES
            try:
                mac_address = nm[host]['addresses']['mac']
                try:
                    manufacturer = nm[host]['vendor'].get(mac_address)
                except Exception as e:
                    manufacturer = None
                    logging.info(str(type(e)) + str(e))
            except Exception as e:
                mac_address = None
                manufacturer = None
                logging.info(str(type(e)) + str(e))

            if mac_address in already_detected_mac_addresses and mac_address is not None:
                current_host = db_session.query(DetectedHost).filter_by(mac_address=mac_address).first()
                db_session.query(DetectedHost).filter_by(mac_address=mac_address).update({DetectedHost.last_seen: NOW})
                logging.info('Present host: ' + str(host))
            else:
                current_host = DetectedHost(address=host, confirmed=False, last_seen=NOW, mac_address=mac_address,
                                            manufacturer=manufacturer, notified=False)
                if network_learning == "active":
                    current_host.confirmed = True
                db_session.add(current_host)
                logging.info('New host: ' + str(host))
            db_session.commit()

        open_ports = []
        for l3_protocol in nm[host].all_protocols():
            ports = list(nm[host][l3_protocol].keys())
            for port in ports:
                subquery = db_session.query(OpenPort).filter(OpenPort.host_id == current_host.id, OpenPort.port == port)
                port_open_recently = db_session.query(subquery.exists()).scalar()
                if port_open_recently:
                    db_session.query(OpenPort).update({OpenPort.last_seen_open: NOW})
                    continue
                service = nm[host][l3_protocol][port]['name']
                if port in SUSPICIOUS_PORTS or service in SUSPICIOUS_SERVICES:
                    open_ports.append(OpenPort(host_id=current_host.id, l3_protocol=l3_protocol, last_seen_open=NOW,
                                               notified=False, port=port, service=service, suspicious=True))
                else:
                    open_ports.append(OpenPort(host_id=current_host.id, l3_protocol=l3_protocol, last_seen_open=NOW,
                                               port=port, service=service, suspicious=False))
                logging.info("Appended port: " + str(port))
        db_session.bulk_save_objects(open_ports)
    db_session.commit()
except Exception as e:
    logging.info(str(type(e)) + str(e))
finally:
    Session.remove()
