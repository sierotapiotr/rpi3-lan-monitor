import subprocess
import re
import logging


def get_mac_address(address):
    mac_address_pattern = r'((?:[0-f]{2}:){5}[0-f]{2})'
    proc = subprocess.run(["/usr/sbin/arp", address], universal_newlines=True, stdout=subprocess.PIPE)
    splited_output = proc.stdout.split("\n")
    most_recent_line = splited_output[-2]
    try:
        mac_address = re.findall(mac_address_pattern, most_recent_line)[0]
    except Exception as e:
        logging.info(str(type(e)) + str(e))
        logging.info("Failed to get mac address.")
        mac_address = None
    return mac_address