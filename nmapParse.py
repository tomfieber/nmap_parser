#!/usr/bin/env python3

# Installation requirements: python-libnmap, argparse, termcolor
# Install instructions: pip3 install python-libnmap, argparse, termcolor

# Usage: pyhton3 nmapParse.py -f <XML file to parse>

import argparse
from libnmap.parser import NmapParser
from termcolor import colored

parser = argparse.ArgumentParser(description='Make constructing the IP table easy')
parser.add_argument('-f', '--file', dest='file', type=str, required=True, help='The file to parse')
parser.add_argument('-q', '--quiet', dest='quiet', action='store_true', help='Suppress the welcome banner and headlines')
args = parser.parse_args()

file = args.file
quiet = args.quiet

ips = {}
listening = {}
port_count = {}

# Print Welcome banner
def greeting():
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

        # Get a dictionary object of all service details
        for service in host.services:

            svcDetails = service.get_dict()
            svcPort = svcDetails['port']

            # Get a count of all ports across hosts
            if svcPort not in port_count.keys():
                port_count[svcPort] = 1
            else:
                port_count[svcPort] += 1

            # Create the list of listening ports
            if ip not in listening.keys():
                listening[ip] = [svcDetails]
            elif ip in listening.keys() and svcDetails not in listening[ip]:
                listening[ip].append(svcDetails)
            else:
                continue


def split_banner(b):
    product = ""
    version = ""
    prodIndex = b.find('product')
    versionIndex = b.find('version')
    extraIndex = b.find('extrainfo')
    if prodIndex != -1:
        if versionIndex != -1:
            product = b[prodIndex+9:versionIndex].strip()
        else:
            product = b[prodIndex+9:extraIndex].strip()
    else:
        product = 'Unknown'
    if versionIndex != -1:
        version = b[versionIndex+9:extraIndex].strip()
    else:
        version = 'Unknown'
    return product, version

def get_port_details(dict):
    port = dict['port']
    protocol = dict['protocol']
    service = dict['service']
    banner = dict['banner']
    product, version = split_banner(banner)
    print(colored(port, 'blue', attrs=['bold']), end=' ')
    print(protocol, service, product, version)

def get_hostnames(ip):
    for host in ips[ip]:
        print(colored(host, "green"))

def print_dict():
    if not quiet:
        print(colored("Use this section to generate tables of".center(60, " "), "grey", "on_yellow"))
        print(colored("ports and services enumerated during testing".center(60, " "), "grey", "on_yellow"))
    for ipaddr in sorted(listening.keys()):
        print()
        print(colored(f"{ipaddr}", "yellow", attrs=['bold']))
        print()
        print(colored("---Hostnames---", "magenta"))
        get_hostnames(ipaddr)
        print()
        print(colored("---Open Ports---", "magenta"))
        for i in range(len(listening[ipaddr])):
            get_port_details(listening[ipaddr][i])
        print()

def count_open_ports():
    if not quiet:
        print(colored("Use this section to generate the distribution".center(60, " "), "grey", "on_yellow"))
        print(colored("chart of listening ports across all hosts".center(60, " "), "grey", "on_yellow"))
        print()
    else:
        print(colored("---Count of all listening ports---", "magenta"))
    for k in sorted(port_count.keys(), key=int):
        print(f"{k} : {port_count[k]}")

if __name__ == '__main__':
    if not quiet:
        greeting()
    populate_dictionaries()
    print_dict()
    count_open_ports()
    
