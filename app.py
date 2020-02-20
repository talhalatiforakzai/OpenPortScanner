# -*- coding: utf-8 -*-
"""
    Open Port Scanner
    ~~~~~~~~~~~~~

    Open port scanner is an application designed to probe a server or host for open ports.

"""
import xmltodict, shlex, json
from subprocess import run
from flask import Flask, request
import mysql.connector

app = Flask(__name__)


# @app.route('/scan_ports', methods=['GET'])
# def scan_ports():

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

    # db = mysql.connector.connect(host="localhost", user="root", passwd="root", database="ops")
    # cursor = db.cursor(dictionary=True)

    ip_address = request.get_json('ip')
    ip_address = ip_address["ip"]
    script_executor(ip=ip_address, usage="Discover Devices")
    devices = parser("Discover Devices")
    #return json.dumps(devices)

    # find ports we pass a list in the arguments
    script_executor(usage="Find Ports")
    ports = parser("Find Ports")
    return json.dumps(ports)

    # Save ip address and mac address in database
    # st = "INSERT INTO devices VALUES ('%s')"
    # cursor.executemany(st, devices_found)
    # db.commit()
    # db.close()
    # return json.dumps(devices)


def parser(usage):
    if usage == "Discover Devices":
        with open('device.xml') as raw_xml:
            nmap_scan = xmltodict.parse(raw_xml.read())
        devices = []
        total_host = len(nmap_scan["nmaprun"]["host"])
        for i in range(total_host - 1):
            devices.append(nmap_scan["nmaprun"]["host"][i]["address"][0]["@addr"])
        devices.append(nmap_scan["nmaprun"]["host"][total_host - 1]["address"]["@addr"])
        # Turn the list into dictionary for std json output
        # devices_found = [{'ip': k, 'mac': v} for k, v in [devices[i: i + 2] for i in range(0, len(devices), 2)]]
        devices_found = [{'ip': k} for k in iter(devices)]
        file = open("iplist.txt", "w")
        for element in devices:
            file.write(element)
            file.write('\n')
        file.close()
        return devices_found
    elif usage == "Find Ports":
        with open('port.xml') as raw_xml:
            nmap_scan = xmltodict.parse(raw_xml.read())
            return nmap_scan


def script_executor(**kwargs):
    if kwargs['usage'] == "Discover Devices":
        cmd = "nmap -sn --open -oX device.xml " + kwargs['ip']
    elif kwargs['usage'] == "Find Ports":
        cmd = "nmap -iL iplist.txt -sUV -sT -T4 -F --version-intensity 0 --open -oX udp.xml"
    args = shlex.split(cmd)
    run(args)


if __name__ == '__main__':
    app.run()
