#!/usr/bin/env python3

# Installation requirements: python-libnmap, argparse, termcolor
# Install instructions: pip3 install python-libnmap, argparse, termcolor

# Usage: pyhton3 nmapParse.py -f <XML file to parse>

import argparse
from libnmap.parser import NmapParser
from termcolor import colored

parser = argparse.ArgumentParser(description='Make constructing the IP table easy')
parser.add_argument('-f', '--file', dest='file', type=str, required=True, help='The file to parse')
args = parser.parse_args()

file = args.file

ips = {}
listening = {}
port_count = {}

# Print Welcome banner
print("-" * 60)
print("Simple Nmap Parser".center(60, " "))
print("Version 1.0".center(60, " "))
print("Author: Tom Fieber, Security Consultant".center(60, " "))
print("-" * 60)        

def populate_dictionaries():
    nmap_parse = NmapParser.parse_fromfile(file)
    for host in nmap_parse.hosts:
        ip = str(host.address)
        if host.hostnames:
            hostname = host.hostnames[0]
        else:
            hostname = "No Hostname"
        if ip not in ips.keys():
            ips[ip] = [hostname]
        else:
            ips[ip].append(hostname)
        for service in host.services:
            svcPort = str(service.port)
            svcProt = str(service.protocol)
            if ip not in listening.keys():
                listening[ip] = {svcPort}
            else:
                listening[ip].add(svcPort)
            if svcPort not in port_count.keys():
                port_count[svcPort] = 1
            else:
                port_count[svcPort] += 1

def get_hostnames(ip):
    for v in ips[ip]:
        print(colored(v, "green"))

def print_dict():
    print(colored("Use this section to generate tables of".center(60, " "), "grey", "on_yellow"))
    print(colored("ports and services enumerated during testing".center(60, " "), "grey", "on_yellow"))
    for k in sorted(listening.keys()):
        print()
        print(colored(f"{k}", "yellow", attrs=['bold']))
        print()
        print(colored("---Hostnames---", "magenta"))
        get_hostnames(k)
        print()
        print(colored("---Open Ports---", "magenta"))
        for v in sorted(listening[k], key=int):
            print(colored(v, "blue"))
        print()
        print()

def count_open_ports():
    print(colored("Use this section to generate the distribution".center(60, " "), "grey", "on_yellow"))
    print(colored("chart of listening ports across all hosts".center(60, " "), "grey", "on_yellow"))
    print()
    for k in sorted(port_count.keys(), key=int):
        print(f"{k} : {port_count[k]}")

if __name__ == '__main__':
    populate_dictionaries()
    print_dict()
    count_open_ports()
    
