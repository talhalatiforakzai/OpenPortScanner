def device_parser(nmap_scan):
    device_lst = []
    keys = ["host", "ip", "mac"]
    values = []
    if nmap_scan["nmaprun"]["host"]:
        for i in nmap_scan["nmaprun"]["host"]:
            if isinstance(i['hostnames'], dict):
                values.append(i['hostnames']['hostname']['@name'])
            else:
                values.append("name not found")
            if isinstance(i['address'], list):
                values.append(i['address'][0]['@addr'])
                values.append(i['address'][1]['@addr'])
            else:
                values.append(i['address']['@addr'])
                values.append("mac not found")
            new_dict = {k: v for k, v in zip(keys, values)}
            values.clear()
            device_lst.append(new_dict)
    return device_lst


def port_parser(nmap_scan):
    device_lst = []
    tcp = []
    udp = []
    for i in nmap_scan["nmaprun"]["host"]:
        if isinstance(i['hostnames'], dict):
            host = i['hostnames']['hostname']['@name']
        else:
            host = "name not found"
        if isinstance(i['address'], list):
            ip = i['address'][0]['@addr']
            mac = i['address'][1]['@addr']
        else:
            ip = i['address']['@addr']
            mac = "mac not found"
        if i['ports'].get('port', 'ports not found') != 'ports not found' and isinstance(i['ports'], dict):
            if isinstance(i['ports']['port'], list):
                for j in i['ports']['port']:
                    if j['@protocol'] == 'tcp':
                        tcp.append(j['@portid'])
                    elif j['@protocol'] == 'udp':
                        udp.append(j['@portid'])
            elif isinstance(i['ports']['port'], dict):
                if i['ports']['port']['@protocol'] == 'tcp':
                    tcp.append(j['@portid'])
                elif i['ports']['port']['@protocol'] == 'udp':
                    udp.append(j['@portid'])
        else:
            del tcp[:]
            del udp[:]
        my_dict = {"mac": mac, "ip": ip, "host": host, "tcp": [], "udp": []}
        for port in tcp: my_dict["tcp"].append(port)
        for port in udp: my_dict["udp"].append(port)
        device_lst.append(my_dict)
        del tcp[:];
        del udp[:];
        mac = "";
        ip = "";
        host = ""
    return device_lst


SCRIPT_COMMANDS = '''#!/usr/bin/env bash 
DIR="$( cd "$( dirname "${{BASH_SOURCE[0]}}" )" && pwd )"
sudo nmap -sn --open -oX device.xml {ip_address}
curl -i -X POST -F file=@$DIR/device.xml http://127.0.0.1:5000/api/port-scanner | sudo sh
nmap -n -sn {ip_address} -oG - | awk '/Up$/{{print $2}}' > iplist.txt
wait $!
sudo nmap -iL iplist.txt -sUV -sT -T4 -F –version-intensity 0 –open -oX port.xml
wait $!
curl -i -X POST -F file=@$DIR/port.xml http://127.0.0.1:5000/api/port-scanner | sudo sh
cat > OPS.sh <<'EOL'
#!/bin/sh
nmap -n -sn {ip_address} -oG - | awk '/Up$/{{print $2}}' > iplistnew.txt     
grep -v -F -x -f iplist.txt iplistnew.txt > searchlist.txt
while [[ -s searchlist.txt ]]
do  
     sudo nmap -iL searchlist.txt -sn --open -oX device.xml 
     sudo nmap -iL searchlist.txt -sUV -sT -T4 -F –version-intensity 0 –open -oX port.xml
     wait $!
     curl -i -X POST -F file=@$DIR/device.xml http://127.0.0.1:5000/api/port-scanner | sudo sh       
     curl -i -X POST -F file=@$DIR/port.xml http://127.0.0.1:5000/api/port-scanner | sudo sh
     cp searchlist.txt iplist.txt
     truncate -s 0 searchlist.txt
     truncate -s 0 iplistnew.txt
done
EOL
chmod +x OPS.sh
(crontab -l ; echo "*/5 * * * * $DIR/OPS.sh")| crontab -'''

