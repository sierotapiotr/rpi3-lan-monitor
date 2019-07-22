import datetime
import json
import logging
import os
import re
import subprocess
import sys

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker, scoped_session
from configparser import ConfigParser

from database.hydra_plugins import PLUGINS_ENCRYPTED, PLUGINS_UNENCRYPTED
from database.database import DetectedHost, CrackedPassword

# ARGUMENTS
RUN_ID = sys.argv[1]
HOST_ID = sys.argv[2]

# CURRENT TIME
NOW = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M")

# PATHS
PATH_INPUT = 'hydra/'
PATH_LOGS = "logs"
PATH_OUTPUT = "output/hydra/{runId}".format(runId=RUN_ID)

if not os.path.exists(PATH_OUTPUT):
    os.makedirs(PATH_OUTPUT)
if not os.path.exists(PATH_LOGS):
    os.makedirs(PATH_LOGS)

# HYDRA TOOL CONFIG
DEFAULT_LOGIN_PASSWORD_FILENAME = 'default-logins-passwords.lst'
DEFAULT_PORT_FOR_SERVICE_FILENAME = 'services-for-ports.json'
HYDRA_PLUGIN_FOR_SERVICE_FILENAME = 'hydra-plugins-for-services.json'

TARGETS_FILENAME = 'targets-'
OUTPUT_FILENAME = 'results-'
OUTPUT_FORMAT = 'json'
JSON_EXTENSION = ".json"

LOGIN_PASSWORD_FLAG = "-C"
TARGET_FLAG = "-M"
OUTPUT_FLAG = "-o"
PARALLEL_CONNECTS_PER_TARGET_FLAG = '-t'
PARALLEL_CONNECTS_PER_TARGET = '4'
OUTPUT_FORMAT_FLAG = "-b"
VERBOSE_FLAG = "-v"
LOOP_AROUND_PASSWORD_FLAG = "-u"
ADDITIONAL_CHECKS_FLAG = "-e"
NULL_PASSWORD_CHECK = 'n'
LOGIN_AS_PASS_CHECK = 's'
REVERSE_LOGIN_AS_PASS_CHECK = 'r'
EXIT_AFTER_FIRST_SUCCESS = "-f"
SSL_FLAG = "-S"

# LOGGING
logging.basicConfig(filename=PATH_LOGS + '/hydra.log', level=logging.INFO, format='%(asctime)s %(message)s')

config = ConfigParser()
config.read(os.path.dirname(os.path.abspath(__file__)) + '/app_config.ini')

current_file_path = os.path.dirname(os.path.abspath(__file__))

sqlalchemy_uri = 'sqlite:///{currentFilePath}/{databaseFilePath}'.format(
    currentFilePath=current_file_path,
    databaseFilePath=config['sqlalchemy']['SQLALCHEMY_DATABASE_FILEPATH'])

# DATABASE SESSION
engine = create_engine(sqlalchemy_uri)
session_factory = sessionmaker(bind=engine, expire_on_commit=False)
Session = scoped_session(session_factory)


def get_hosts_for_plugins():
    logging.info('Getting plugins...')
    plugins_appended = {}

    with open(PATH_INPUT + HYDRA_PLUGIN_FOR_SERVICE_FILENAME, 'r') as infile:
        service_to_plugins_dict = json.load(infile)

    session = Session()
    latest_detection_datetime = session.query(func.max(DetectedHost.last_seen)).scalar()
    hosts = session.query(DetectedHost).filter(DetectedHost.last_seen == latest_detection_datetime).all()

    for host in hosts:
        for port in host.open_ports:
            port_nr = port.port
            service = port.service
            try:
                plugins_for_current_service = service_to_plugins_dict[service]
                logging.info('Appending {service} to plugins.'.format(service=service))
                append_plugins_to_dict(plugins_appended, plugins_for_current_service, host, port_nr)
            except KeyError:
                logging.info('Didn\'t find plugin for {service}'.format(service=service))
            except Exception as e:
                logging.info(str(type(e)) + str(e))
    return plugins_appended


def append_plugins_to_dict(plugins_appended, plugins_for_current_service, host_name, port):
    for plugin in plugins_for_current_service:
        if plugin not in plugins_appended.keys():
            plugins_appended[plugin] = {}
        plugins_appended[plugin][host_name] = port


def create_file_with_targets(plugins_dict, plugin):
    with open(os.path.join(PATH_OUTPUT, TARGETS_FILENAME + plugin), 'w') as targets_file:
        for host_obj, port in plugins_dict[plugin].items():
            targets_file.write("{host}:{port}\n".format(host=host_obj.address, port=port))


def run_hydra(plugin):
    cmd_hydra = ['hydra', LOGIN_PASSWORD_FLAG, os.path.join(PATH_INPUT, DEFAULT_LOGIN_PASSWORD_FILENAME),
                 OUTPUT_FLAG, os.path.join(PATH_OUTPUT, OUTPUT_FILENAME + plugin), PARALLEL_CONNECTS_PER_TARGET_FLAG,
                 PARALLEL_CONNECTS_PER_TARGET, OUTPUT_FORMAT_FLAG, OUTPUT_FORMAT, VERBOSE_FLAG, TARGET_FLAG,
                 os.path.join(PATH_OUTPUT, TARGETS_FILENAME + plugin), LOOP_AROUND_PASSWORD_FLAG, EXIT_AFTER_FIRST_SUCCESS]
    if plugin in PLUGINS_ENCRYPTED:
        cmd_hydra += [SSL_FLAG, plugin]
    else:
        cmd_hydra += [plugin]

    try:
        logging.info('Running hydra for {service}'.format(service=plugin))
        proc = subprocess.run(cmd_hydra, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info('Run completed for {service}'.format(service=plugin))
    except Exception as e:
        logging.info('Scan for {service} failed'.format(service=plugin))
        logging.info(str(type(e)) + str(e))


def insert_result_into_database(plugin):
    session = Session()
    passwords_cracked = 0

    with open(os.path.join(PATH_OUTPUT, OUTPUT_FILENAME + plugin)) as infile:
        data = json.load(infile)
        for result in data['results']:
            hydra_result = CrackedPassword(detected_host_id=HOST_ID, service=result['service'], port=result['port'],
                                           login=result['login'])
            session.add(hydra_result)
            passwords_cracked += 1

    host = session.query(DetectedHost).filter(DetectedHost.id == HOST_ID).first()
    host.cracked_passwords = passwords_cracked
    session.commit()
    Session.remove()


def main():
    logging.info('Starting hydra script for host_id=' + str(HOST_ID))
    hosts_for_plugins = get_hosts_for_plugins()
    plugins = hosts_for_plugins.keys()
    for plugin in plugins:
        create_file_with_targets(hosts_for_plugins, plugin)
        run_hydra(plugin)
        try:
            insert_result_into_database(plugin)
        except Exception as e:
            logging.info('Failed to insert results into database')
            logging.info(str(type(e)) + str(e))


if __name__ == '__main__':
    main()
