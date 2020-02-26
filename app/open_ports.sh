#!/usr/bin/env bash
nmap -iL iplist.txt  -sUV -sT -T4 -F --version-intensity 0 --open -oX port.xml