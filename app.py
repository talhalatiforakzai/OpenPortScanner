# -*- coding: utf-8 -*-
"""
    Open Port Scanner
    ~~~~~~~~~~~~~

    Open port scanner is an application designed to probe a server or host for open ports.

"""
import xmltodict, shlex, json
from subprocess import run
from flask import Flask, request

app = Flask(__name__)


@app.route('/discover_devices', methods=['GET'])
def discover_host():
    """ Discover devices on a network

    This function accepts ip and forms a command line string which is passed to shlex
    that parses the string into shell-like syntax, the flag -sn tells Nmap not to do a
    port scan after host discovery, and only print out the available hosts that responded
    to the host discovery probes.


    Parameters
    ----------
        ip : string
            ip address of the network to be scanned for host discovery

    Returns
    -------
        json
            a jason array containing the information of devices on the network

    """

    ip = request.get_json('ip')
    cmd = "nmap -sn --open -oX scan.xml " + ip["ip"] 
    args = shlex.split(cmd)
    run(args)

    with open('scan.xml') as raw_xml:
        nmap_scan = xmltodict.parse(raw_xml.read())

    devices = []
    for i in range(len(nmap_scan["nmaprun"]["host"])):
        devices.append(nmap_scan["nmaprun"]["host"][i]["address"])

    return json.dumps(devices)


if __name__ == '__main__':
    app.run()
