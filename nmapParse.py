#!/usr/bin/env python3

# Installation requirements: python-libnmap, argparse, termcolor
# Install instructions: pip3 install python-libnmap, argparse, termcolor

# Usage: pyhton3 nmapParse.py -f <XML file to parse>

import argparse
from libnmap.parser import NmapParser
from termcolor import colored

parser = argparse.ArgumentParser(
    description='Make constructing the IP table easy')
parser.add_argument('-f', '--file', dest='file', type=str,
                    required=True, help='The file to parse')
parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                    help='Suppress the welcome banner and headlines')
parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                    help='List all ports with duplicates')
parser.add_argument('-p', '--ports', dest='ports',
                    action='store_true', help='Show detailed port information')
args = parser.parse_args()

file = args.file
quiet = args.quiet
verbose = args.verbose
show_port_details = args.ports


ips = {}
ports = {}
port_count = {}


# Print Welcome banner
def greeting():
    print("-" * 60)
    print("Simple Nmap-Parser".center(60, " "))
    print("Version 0.1.0".center(60, " "))
    print("@tomfieber".center(60, " "))
    print("-" * 60)


def check_open(state):
    return state == "open"


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
            svcState = svcDetails['state']

            port_is_open = check_open(svcState)

            if port_is_open:

                # Get a count of all ports across hosts
                if svcPort not in port_count.keys():
                    port_count[svcPort] = 1
                else:
                    port_count[svcPort] += 1

                # Create the list of listening ports
                if not verbose:
                    if ip not in ports.keys():
                        ports[ip] = [svcDetails]
                    elif ip in ports.keys() and svcDetails not in ports[ip]:
                        ports[ip].append(svcDetails)
                    else:
                        continue
                else:
                    if ip not in ports.keys():
                        ports[ip] = [svcDetails]
                    else:
                        ports[ip].append(svcDetails)


def split_banner(b):
    banner = b.split()
    firstword = banner[0]
    lastword = banner[-1]
    for word in banner:
        if word.endswith(':'):
            if word is firstword:
                print(word.capitalize(), end=" ")
            else:
                print(f'\n{word.capitalize()}', end=" ")
        elif word is lastword:
            print(word)
            print()
        else:
            print(word, end=" ")


def get_port_details(dict):
    port = dict['port']
    protocol = dict['protocol']
    service = dict['service']
    banner = dict['banner']
    print(colored(f'[*] {port}', 'blue', attrs=['bold']), end=" ")
    print(protocol, end=" ")
    print(service)
    if show_port_details:
        try:
            split_banner(banner)
        except IndexError:
            print("Product and version unknown")
            print()


def get_hostnames(ip):
    for host in ips[ip]:
        print(colored(host, "green"))


def print_dict():
    if not quiet:
        print(colored("Use this section to generate tables of".center(
            60, " "), "grey", "on_yellow"))
        print(colored("ports and services enumerated during testing".center(
            60, " "), "grey", "on_yellow"))
        print()
    for ipaddr in sorted(ports.keys()):
        print(colored(f"[+] {ipaddr}", "yellow", attrs=['bold']))
        print()
        print(colored("---Hostnames---", "magenta"))
        get_hostnames(ipaddr)
        print()
        print(colored("---Open Ports---", "magenta"))
        for i in range(len(ports[ipaddr])):
            get_port_details(ports[ipaddr][i])
        print()


def count_open_ports():
    if not quiet:
        print(colored("Use this section to generate the distribution".center(
            60, " "), "grey", "on_yellow"))
        print(colored("chart of ports ports across all hosts".center(
            60, " "), "grey", "on_yellow"))
        print()
    else:
        print(colored("---Count of all ports ports---", "magenta"))
    for k in sorted(port_count.keys(), key=int):
        print(f"{k} : {port_count[k]}")


if __name__ == '__main__':
    try:
        if not quiet:
            greeting()
        populate_dictionaries()
        print_dict()
        count_open_ports()
    except Exception:
        print("Something went wrong. Check your nmap XML file and try again.")
