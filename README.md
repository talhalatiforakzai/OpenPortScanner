# OpenPortScanner
Open port scanner is an application designed to probe a server or host for open ports.

## Usage
Open terminal and type the following 
```
sudo docker-compose up
```
#### http://localhost:5000/OPS 
Discover ip address and open ports of active devices on a network and returns a json array.

Download bash script

![alt text](https://i.ibb.co/C5QQ4HZ/ds.png)
```http
GET /OPS HTTP/1.1
Host: localhost:5000
Content-Type: application/json

{
	"ip" : "192.168.100.1/24"
}
```

CronJob set to True

![alt text](https://i.ibb.co/TMqkNZ2/2.png)
```http
POST /OPS HTTP/1.1
Host: localhost:5000
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="discover_device.sh"
Content-Type: application/x-sh

(data)
----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="cron_job"

True
----WebKitFormBoundary7MA4YWxkTrZu0gW

```


## Functions
<details>
  <summary>open_port_scanner()</summary>
  
  ```python
    def open_port_scanner():
    """ Discover ip address and open ports of active devices on a network

    :return ports: (dict) json containing ip address and open ports on the network

    """

    if request.method == 'GET':
        return download_script()
    elif request.method == 'POST':
        cronJob = request.form['cron_job']
        if cronJob == "True":
            print("Cron job")
            return cron_job()
        elif cron_job() == "False":
            print("not a cron job")
            post_file()
            discoverDevices()
            # Iterating over active devices and finding open ports
            script_executor(usage="Find Ports")
            ports = parser("Find Ports")
            return json.dumps(ports)
  ```
</details>
<details>
  <summary>cron_job()</summary>
  
  ```python
    def cron_job():
    """ This function calls a worker function every 5 min and checks for new devices and ports

        :return: (string) acknowledgement for successful execution

    """
    post_file()
    discoverDevices()
    # retrieve ip to be used for cronJob
    with open("app/script/discover_device.sh", "r") as filehandle:
        line = filehandle.readlines()[-1]
    ip_address = line.split(' ')[-1]

    sched = BackgroundScheduler(daemon=True)
    sched.add_job(worker, 'interval', args=[ip_address], minutes=5)
    sched.start()
    return "cron job running, std output displaying the ports and devices"
  ```
</details>
<details>
  <summary>worker(network)</summary>
  
  ```python
    def worker(network):
    """ This function executes every 5 min to check for new devices and ports on network, it receives an
        ip address it then trie to fetch old devices from database if found compares it to new device
        and using set theory gets the list of newly discovered devices for which ports are scanned else
        it searches for devices on network considers it new devices

    """
    db = dbConnection()
    cursor = db.cursor()
    try:
        st = """SELECT * FROM devices"""
        cursor.execute(st)
        old_devices = [item for item in cursor.fetchall()]
        db.commit()
        db.close()
    except Exception as error:
        return error
    else:
        if old_devices:
            script_formulator(network)
            script_executor(usage="Discover Devices")
            new_devices = parser("Discover Devices")
            new_devices = list(({*new_devices} - {*old_devices}))
            file = open("app/script/iplist.txt", "w")
            for element in new_devices:
                file.write(element)
                file.write('\n')
            file.close()
            script_executor(usage="Find Ports")
            ports = parser("Find Ports")
            print(json.dumps(ports))
        else:
            script_formulator(network)
            time.sleep(5)
            script_executor(usage="Discover Devices")
            new_devices = parser("Discover Devices")
            new_devices = [(x,) for x in new_devices]
            st = """INSERT INTO devices VALUES (%s)"""
            cursor.executemany(st, new_devices)
            db.commit()
            db.close()
            script_executor(usage="Find Ports")
            ports = parser("Find Ports")
            print(json.dumps(ports))

  ```
</details>
<details>
  <summary>download_script()</summary>
  
  ```python
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
    return send_file("script/discover_device.sh", as_attachment=True)
  ```
</details>
<details>
  <summary>script_formulator(ip_address)</summary>
  
  ```python
    def script_formulator(ip_address):
    """ This function takes ip and forms a bash script and saves it to script directory for later use """
    s = ["#!/usr/bin/env bash", "nmap -sn --open -oX device.xml " + ip_address]
    with open('app/script/discover_device.sh', 'w') as filehandle:
        for itm in s:
            filehandle.write('%s\n' % itm)
  ```
</details>
<details>
  <summary>script_executor()</summary>
  
  ```python
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
  ```
</details>
<details>
  <summary>post_file()</summary>
  
  ```python  
    def post_file():
        """ This takes bash script uploaded by user and saves it to script directory to be executed """
        f = request.files['file']
        f.save(os.path.join("app/script", secure_filename(f.filename)))
  ```
</details>
<details>
  <summary>discoverDevices()</summary>
  
  ```python  
    def discoverDevices():
    """Discover new devices """
    script_executor(usage="Discover Devices")
    devices = parser("Discover Devices")

    db = dbConnection()
    cursor = db.cursor()
    devices = [(x,) for x in devices]
    st = """INSERT INTO devices VALUES (%s)"""
    cursor.executemany(st, devices)
    db.commit()
    db.close()

  ```
</details>
<details>
  <summary>dbConnection()</summary>
  
  ```python  
    def dbConnection():
    """ Configuration for mysql database """
    try:
        db = mysql.connector.connect(host="db", user="root", port="3306", passwd="root", database="OPS")
        return db
    except Exception as error:
        return error

  ```
</details>
<details>
  <summary>parser(usage)</summary>
  
  ```python  
    def parser(usage):
    """ Parses the xml output into dictionary and then saves the ip address into a txt file that will be
        used to find open ports

        :param usage: (string) object that tells the function to either Discover new device or find open ports
        :return device: (list) object containing the ip address of the active devices on network
        :return ports: (dict) array of dictionary objects containing information about open ports and devices

    """

    if usage == "Discover Devices":
        with open('app/script/device.xml') as raw_xml:
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
        file = open("app/script/iplist.txt", "w")
        for element in devices:
            file.write(element)
            file.write('\n')
        file.close()
        return devices
    elif usage == "Find Ports":
        with open('app/script/port.xml') as raw_xml:
            nmap_scan = xmltodict.parse(raw_xml.read())
            ports = nmap_scan["nmaprun"]["host"]
            return ports
  ```
</details>
<details>
  <summary>script_executor(**kwargs)</summary>
  
  ```python  
 def script_executor(**kwargs):
    """ Executes the bash scripts, gives execute permission to the bash scripts."""
    if kwargs['usage'] == "Discover Devices":
        # Set executable permission
        subprocess.call(["chmod", "-R", "775", "app/script"])
        subprocess.call(['./discover_device.sh'], cwd="app/script")
    elif kwargs['usage'] == "Find Ports":
        subprocess.call(["chmod", "-R", "775", "app/script"])
        subprocess.call(['./open_ports.sh'], cwd="app/script")
  ```
</details>
