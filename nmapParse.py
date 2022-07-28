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
parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Show the ports for every host on every IP even if there are duplicates')
parser.add_argument('-p', '--ports', dest='ports', action='store_true', help='Show detailed port information')
args = parser.parse_args()

file = args.file
quiet = args.quiet
verbose = args.verbose
show_port_details = args.ports


ips = {}
listening = {}
port_count = {}


# Print Welcome banner
def greeting():
    print(" _   _                             _____")                    
    print("| \ | |                           |  __ \\")                   
    print("|  \| |_ __ ___   __ _ _ __ ______| |__) |_ _ _ __ ___  ___")
    print("| . ` | '_ ` _ \ / _` | '_ \______|  ___/ _` | '__/ __|/ _ \\")
    print("| |\  | | | | | | (_| | |_) |     | |  | (_| | |  \__ \  __/")
    print("|_| \_|_| |_| |_|\__,_| .__/      |_|   \__,_|_|  |___/\___|")
    print("                      | |")                                   
    print("                      |_|")                                   
                                 
    print()
    print("Version 0.1.0")
    print("@tomfieber")
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
                    if ip not in listening.keys():
                        listening[ip] = [svcDetails]
                    elif ip in listening.keys() and svcDetails not in listening[ip]:
                        listening[ip].append(svcDetails)
                    else:
                        continue
                else:
                    if ip not in listening.keys():
                        listening[ip] = [svcDetails]
                    else:
                        listening[ip].append(svcDetails)

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
        except:
            print("Product and version unknown")
            print()
    
def get_hostnames(ip):
    for host in ips[ip]:
        print(colored(host, "green"))

def print_dict():
    if not quiet:
        print(colored("Use this section to generate tables of".center(60, " "), "grey", "on_yellow"))
        print(colored("ports and services enumerated during testing".center(60, " "), "grey", "on_yellow"))
        print()
    for ipaddr in sorted(listening.keys()):
        print(colored(f"[+] {ipaddr}", "yellow", attrs=['bold']))
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
    try:
        if not quiet:
            greeting()
        populate_dictionaries()
        print_dict()
        count_open_ports()
    except:
        print("Something went wrong. Check your nmap XML file and try again.")
    
