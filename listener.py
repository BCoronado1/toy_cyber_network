import logging
import os
import re
import subprocess

import netifaces


def get_iface():
    toy_subnet = os.getenv("TOY_SUBNET")
    first_three_octets: str = ".".join(toy_subnet.split(".")[:3])
    for iface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(iface)
        for if_idx, if_list in addresses.items():
            for if_item in if_list:
                if "addr" in if_item:
                    addr = if_item["addr"]
                    if addr.startswith(first_three_octets):
                        return iface
    return None


if __name__ == "__main__":
    log_file_name = "listener.log"
    rootLogger = logging.getLogger()
    rootLogger.setLevel(logging.INFO)

    log_dir = "/var/log"
    log_location = f"{log_dir}/{log_file_name}"
    fileHandler = logging.FileHandler(log_location)
    rootLogger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    rootLogger.addHandler(consoleHandler)
    logging.basicConfig(level=logging.INFO)

    target_iface = get_iface()
    command = ["tcpdump", "-n", "-tttt", "-i", target_iface]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    tcp_dump_regex = re.compile(r'\d{1,2}:\d{1,2}:\d{1,2}.\d{6} IP '
                                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,5} > '
                                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,5}:')

    while True:
        byte_str = proc.stdout.readline().strip()
        line = byte_str.decode().strip()
        if tcp_dump_regex.search(line):
            logging.info(line)
