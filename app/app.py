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


@app.route('/OPS', methods=['GET'])
def open_port_scanner():
    """ Discover ip address and open ports of active devices on a network

    :return ports: (dict) object containing ip address and open ports on the network

    """

    ip_address = request.get_json('ip')
    ip_address = ip_address["ip"]
    script_executor(ip=ip_address, usage="Discover Devices")
    devices = parser("Discover Devices")
    dbConnection(devices)

    # Iterating over active devices and finding open ports
    script_executor(usage="Find Ports")
    ports = parser("Find Ports")
    return json.dumps(ports)


def dbConnection(devices):
    """ Save ip address in mysql database

        :param devices: (list) object containing the active addresses found on the network

        """
    try:
        db = mysql.connector.connect(host="localhost", user="root", port="3306", passwd="root", database="OPS")
        cursor = db.cursor()
        devices = [(x,) for x in devices]
        st = """INSERT INTO devices VALUES (%s)"""
        cursor.executemany(st, devices)
        db.commit()
        db.close()
    except Exception as error:
        return error


def parser(usage):
    """ Parses the xml output into dictionary and then saves the ip address into a txt file that will be
        used to find open ports

        :param usage: (string) object that tells the function to either Discover new device or find open ports
        :return device: (list) object containing the ip address of the active devices on network
        :return ports: (dict) array of dictionary objects containing information about open ports and devices

    """

    if usage == "Discover Devices":
        with open('device.xml') as raw_xml:
            nmap_scan = xmltodict.parse(raw_xml.read())
        devices = []
        total_host = len(nmap_scan["nmaprun"]["host"])

        # this block parses the ip according to the object returned
        if nmap_scan["nmaprun"]["host"][0]["address"]["@addr"]:
            for i in range(total_host):
                devices.append(nmap_scan["nmaprun"]["host"][i]["address"]["@addr"])
        elif nmap_scan["nmaprun"]["host"][0]["address"][0]["@addr"]:
            for i in range(total_host-1):
                devices.append(nmap_scan["nmaprun"]["host"][i]["address"][0]["@addr"])
            # Local host is located outside the list so it needs to be parsed outside the loop
            devices.append(nmap_scan["nmaprun"]["host"][total_host - 1]["address"]["@addr"])

        # Active devices ip address saved in a txt file later to be used to find open ports and save ip address in DB
        file = open("iplist.txt", "w")
        for element in devices:
            file.write(element)
            file.write('\n')
        file.close()
        return devices
    elif usage == "Find Ports":
        with open('port.xml') as raw_xml:
            nmap_scan = xmltodict.parse(raw_xml.read())
            ports = nmap_scan["nmaprun"]["host"]
            return ports


def script_executor(**kwargs):
    """ Executes the NMAP commands in subprocess and use shlex to parses the string into shell-like syntax that is
        required by popenargs.

           :param usage: (string) object that tells the function to either Discover new device or find open ports
           :return ip: (string) ip address of the network
           :return none:

       """
    if kwargs['usage'] == "Discover Devices":
        cmd = "nmap -sn --open -oX device.xml " + kwargs['ip']
    elif kwargs['usage'] == "Find Ports":
        cmd = "nmap -iL iplist.txt -sUV -sT -T4 -F --version-intensity 0 --open -oX port.xml"
    args = shlex.split(cmd)
    run(args)


if __name__ == '__main__':
    app.run(host='0.0.0.0')
