# -*- coding: utf-8 -*-
"""
    Open Port Scanner
    ~~~~~~~~~~~~~

    Open port scanner is an application designed to probe a server or host for open ports.

"""
import xmltodict, json, subprocess, time, os
from flask import Flask, request, send_file
import mysql.connector
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.route('/OPS', methods=['GET', 'POST'])
def open_port_scanner():
    """ Discover ip address and open ports of active devices on a network

    :return ports: (dict) json containing ip address and open ports on the network

    """

    if request.method == 'GET':
        return download_script()
    elif request.method == 'POST':
        cronJob = request.form['cron_job']
        if cronJob == "True":
            return cron_job()
        elif cronJob == "False":
            post_file()
            discoverDevices()
            # Iterating over active devices and finding open ports
            script_executor(usage="Find Ports")
            ports = parser("Find Ports")
            return json.dumps(ports)


def cron_job():
    """ This function calls a worker function every 5 min and checks for new devices and ports

        :return: (string) acknowledgement for successful execution

    """
    post_file()
    print("************************ DISCOVERED DEVICES INFO ************************", flush=True)
    discoverDevices()
    print("************************ DISCOVERED PORTS INFO ************************", flush=True)
    script_executor(usage="Find Ports")
    # retrieve ip to be used for cronJob
    with open("discover_device.sh", "r") as filehandle:
        line = filehandle.readlines()[-1]
    ip_address = line.split(' ')[-1]

    sched = BackgroundScheduler(daemon=True)
    sched.add_job(worker, 'interval', args=[ip_address], minutes=5)
    sched.start()
    return "cron job running, std output displaying the ports and devices"


def worker(network):
    """ This function executes every 5 min to check for new devices and ports on network, it receives an
        ip address it then trie to fetch old devices from database if found compares it to new device
        and using set theory gets the list of newly discovered devices for which ports are scanned else
        it searches for devices on network considers it new devices

    """
    print("************************ WORKER STARTED ************************", flush=True)
    db = dbConnection()
    cursor = db.cursor()
    st = """SELECT * FROM devices"""
    cursor.execute(st)
    old_devices = [item for item in cursor.fetchall()]
    old_devices = [x[0] for x in old_devices]
    db.commit()
    db.close()
    if old_devices:
        script_formulator(network)
        print("************************ DISCOVERED DEVICES INFO ************************", flush=True)
        script_executor(usage="Discover Devices")
        devices = parser("Discover Devices")
        new_devices = list(({*devices} - {*old_devices}))
        for it in new_devices:
            print(it)
            print("\n")
        if new_devices:
            print("************************ NEW DEVICES FOUND ************************", flush=True)
            file = open("iplist.txt", "w")
            for element in new_devices:
                file.write(element)
                file.write('\n')
            file.close()
            print("************************ DISCOVERED PORTS INFO ************************", flush=True)
            script_executor(usage="Find Ports")
        else:
            print("************************ NEW DEVICES NOT FOUND ************************", flush=True)
    else:
        print("************************ No devices in database Running Scan ************************", flush=True)
        script_formulator(network)
        time.sleep(5)
        print("************************ DISCOVERED DEVICES INFO ************************", flush=True)
        script_executor(usage="Discover Devices")
        new_devices = parser("Discover Devices")
        new_devices = [(x,) for x in new_devices]
        st = """INSERT IGNORE INTO devices VALUES (%s)"""
        cursor.executemany(st, new_devices)
        db.commit()
        db.close()
        print("************************ DISCOVERED PORTS INFO ************************", flush=True)
        script_executor(usage="Find Ports")



def download_script():
    """ This function takes ip from user and passes it to script_formulator() which form a bash script
        that user can download

            :return: (file) bash script is returned

    """
    ip_address = request.get_json('ip')
    ip_address = ip_address["ip"]
    script_formulator(ip_address)
    # Since flask only supports static file, before sending we have to wait until the file is closed
    time.sleep(10)
    return send_file("discover_device.sh", as_attachment=True)


def script_formulator(ip_address):
    """ This function takes ip and forms a bash script and saves it to root directory for later use """
    s = ["#!/usr/bin/env bash", "nmap -sn --open -oX device.xml " + ip_address]
    with open('discover_device.sh', 'w') as filehandle:
        for itm in s:
            filehandle.write('%s\n' % itm)


def post_file():
    """ This takes bash script uploaded by user and saves it to script directory to be executed """
    f = request.files['file']
    f.save(secure_filename(f.filename))


def discoverDevices():
    """Discover new devices """
    script_executor(usage="Discover Devices")
    devices = parser("Discover Devices")

    db = dbConnection()
    cursor = db.cursor()
    devices = [(x,) for x in devices]
    st = """INSERT IGNORE INTO devices VALUES (%s)"""
    cursor.executemany(st, devices)
    db.commit()
    db.close()


def dbConnection():
    """ Configuration for mysql database """
    try:
        db = mysql.connector.connect(host="db", user="root", port="3306", passwd="root", database="OPS")
        return db
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
            for i in range(total_host - 1):
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
    """ Executes the bash scripts, gives execute permission to the bash scripts.
    :param kwargs:
    """
    if kwargs['usage'] == "Discover Devices":
        # Set executable permission
        subprocess.call(["chmod", "775", "discover_device.sh"])
        subprocess.call(['./discover_device.sh'])
    elif kwargs['usage'] == "Find Ports":
        subprocess.call(["chmod", "775", "open_ports.sh"])
        subprocess.call(['./open_ports.sh'])


if __name__ == '__main__':
    app.run(host='0.0.0.0')
