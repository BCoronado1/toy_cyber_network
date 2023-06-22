import logging
import socket
import subprocess
import time
from typing import List

import nmap

if __name__ == "__main__":
    log_file_name = "attacker.log"
    log_format = "%(asctime)s [%(threadName)-12.12s] [%(levelname)-7.7s]  %(message)s"

    logFormatter = logging.Formatter(log_format)
    rootLogger = logging.getLogger()
    rootLogger.setLevel(logging.INFO)

    log_dir = "/var/log"
    log_location = f"{log_dir}/{log_file_name}"
    fileHandler = logging.FileHandler(log_location)
    fileHandler.setFormatter(logFormatter)
    rootLogger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    rootLogger.addHandler(consoleHandler)
    logging.basicConfig(level=logging.INFO)

    subprocess.call(["ethtool", "-K", "eth0", "tx", "off"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    hostname: str = socket.gethostname()
    ip_address: str = socket.gethostbyname(hostname)
    subnet: str = ".".join(list(ip_address.split(".")[:3])) + ".0/24"
    nm = nmap.PortScanner()
    logging.info(f"INITIALIZE - Configuring attacker with hostname {hostname} on ip {ip_address}. "
                 f"Using subnet {subnet}.")
    while True:
        time.sleep(5)
        logging.info(f"START - Attacker start attack loop!")
        logging.info(f"PING SCAN - Attacker perform ping scan of network for available hosts")
        nm.scan(hosts=subnet, arguments="-n -sn")
        alive_hosts: List[str] = nm.all_hosts()
        logging.info(f"Attacker found the following hosts on the network: {alive_hosts}.")
        logging.info(f"SERVICE SCAN - Attacker perform ping scan of network for available hosts.")
        nm.scan(hosts=subnet, arguments="-n -sV")
        for host_ip in nm.all_hosts():
            logging.info("----------------------------------------------------")
            logging.info(f"Host : {host_ip})")
            logging.info(f"State : {nm[host_ip].state()}")
            for proto in nm[host_ip].all_protocols():
                logging.info("----------")
                logging.info(f"Protocol : {proto}")
                lport = list(nm[host_ip][proto].keys())
                lport.sort()
                for port in lport:
                    logging.info(f"port : {port}\tstate : {nm[host_ip][proto][port]['state']}")
        logging.info(f"END - Attacker perform ping scan of network for available hosts.")
