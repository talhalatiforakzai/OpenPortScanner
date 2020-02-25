#!/usr/bin/env bash
sudo nmap -iL iplist.txt -sT -sUV -T4 -F --version-intensity 0 --open -oX port.xml