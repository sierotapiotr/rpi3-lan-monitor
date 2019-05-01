import logging


def findUntrustedMacAddresses(trusted_hosts, recent_hosts):
    trusted_addresses = {host.mac_address for host in trusted_hosts}
    recent_addresses = {host.mac_address for host in recent_hosts}
    untrusted_addresses = recent_addresses - trusted_addresses
    return untrusted_addresses
