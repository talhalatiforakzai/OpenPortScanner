#!/usr/bin/env bash 
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
sudo nmap -sn --open -oX device.xml 192.168.100.0/24
curl -i -X POST -F file=@$DIR/device.xml http://127.0.0.1:5000/api/port-scanner | sudo sh
nmap -n -sn 192.168.100.0/24 -oG - | awk '/Up$/{print $2}' > iplist.txt
wait $!
sudo nmap -iL iplist.txt -sUV -sT -T4 -F –version-intensity 0 –open -oX port.xml
wait $!
curl -i -X POST -F file=@$DIR/port.xml http://127.0.0.1:5000/api/port-scanner | sudo sh
cat > OPS.sh <<'EOL'
#!/bin/sh
nmap -n -sn 192.168.100.0/24 -oG - | awk '/Up$/{print $2}' > iplistnew.txt     
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
(crontab -l ; echo "*/5 * * * * $DIR/OPS.sh")| crontab -