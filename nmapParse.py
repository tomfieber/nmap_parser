#!/usr/bin/env python3

"""A very simple Nmap XML parser to make pentest reporting a bit easier.

Description:
    This tool takes in one Nmap XML file, parses it, and returns a list of
    hostnames under the appropriate IP address. It also shows a count of all
    open ports across all hosts in-scope to make creating the chart of
    listening services a bit easier.

    Example:
        python3 nmapParse.py -f <FILE TO PARSE>

    Options:
        -f/--file: The file[s] to parse. This option is required. Separate multiple XML files on the command line with a space. 
        -q/--quiet: Suppresses the welcome banner and section headers.
        -p/--ports: Shows verbose port details beyond just port, protocol,
                    and service.
        -v/--verbose: Shows all the open ports from every host associated with
                    an IP address, even if there are duplicates.

Author:
    Tom Fieber (@tomfieber)

"""

import argparse
from libnmap.parser import NmapParser
from termcolor import colored
from docx import Document
from Modules.export import exportCsv
from Modules.generateAppendix import AppendixGenerator
from Modules.keyFunctions import split_banner
from Modules.parseDehashed import ParseDehashed
import os


class NParse(object):
    """Parses an Nmap XML file"""

    def __init__(self, file, options=None):
        self.file = file
        self.options = options

    def check_open(self, state):
        """Checks if a port is open.

        Args:
            state: The port state from Nmap.

        Returns:
            True if the port is open, False if it is not.
        """
        return state == "open"

    def populate_dictionaries(self, ips, pd, pc, srvc):
        """Parses data from the XML file and stores it in dictionaries for later use.

        Args:
            ips: The dictionary you plan to use to store IPs and hostnames.
            pd: The dictionary for storing port details
            pc: The dictionary for storing a count of open ports across all hosts.

        Returns:
            Doesn't return anything, but all dictionaries will be populated.
        """
        nmap_parse = NmapParser.parse_fromfile(self.file)
        for host in nmap_parse.hosts:
            ip = str(host.address)
            if host.hostnames:
                hostname = host.hostnames[0]
            else:
                hostname = ''
            if ip not in ips.keys():
                ips[ip] = [hostname]
            else:
                ips[ip].append(hostname)

            # Get a dictionary object of all service details
            for service in host.services:

                svcDetails = service.get_dict()
                svcPort = svcDetails['port']
                svcState = svcDetails['state']
                svcName = svcDetails['service']
                svcProtocol = svcDetails['protocol']
                banner = svcDetails['banner']
                svcProduct, svcVersion = split_banner(banner)

                port_is_open = self.check_open(svcState)

                if port_is_open:

                    # Get a count of all ports across hosts
                    if svcPort not in pc.keys():
                        pc[svcPort] = {'protocol': svcProtocol, 'count': 1}
                    else:
                        pc[svcPort]['count'] += 1

                    # Create the list of listening ports
                    if not verbose:
                        if ip not in pd.keys():
                            pd[ip] = [svcDetails]
                        elif ip in pd.keys() and svcDetails not in pd[ip]:
                            pd[ip].append(svcDetails)
                        else:
                            continue
                    else:
                        if ip not in pd.keys():
                            pd[ip] = [svcDetails]
                        else:
                            pd[ip].append(svcDetails)

                    details = (ip, svcPort, svcProtocol, svcProduct, svcVersion)
                    if svcName not in srvc.keys():
                        srvc[svcName] = {'details': [details]}
                    elif svcName in srvc.keys() and details not in srvc[svcName]['details']:
                        srvc[svcName]['details'].append(details)


class DisplayAll(object):
    """Displays port informtation from the provided XML files"""

    def __init__(self, ip_dict, ports_dict, port_count_dict):
        self.ips = ip_dict
        self.ports = ports_dict
        self.port_count = port_count_dict

    def greeting(self):
        """Prints a welcome banner."""
        print("-" * 60)
        print("Simple Nmap-Parser".center(60, " "))
        print("Version 0.2.0".center(60, " "))
        print("Tom Fieber (@tomfieber)".center(60, " "))
        print("-" * 60)

    def split_banner(self, b):
        """Takes a banner object from libnmap and splits it up.

        Args:
            b: The banner string you want to parse

        Returns:
            Nothing
        """
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

    def get_port_details(self, dict, file):
        """Gets the port details from the nmap results for each port.

        Args:
            dict: The dictionary containing the port details.

        Returns:
            Nothing
        """
        port = dict['port']
        protocol = dict['protocol']
        service = dict['service']
        banner = dict['banner']
        file.write(f"[*] {port} ")
        file.write(f"{protocol} ")
        file.write(f"{service}\n")
        if show_port_details:
            try:
                self.split_banner(banner)
            except IndexError:
                print("Product and version unknown")
                print()

    def get_hostnames(self, ip):
        """Reads the hostnames associated with a given IP address

        Args:
            ip: The IP for which you want to retrieve hostnames

        Returns:
            Nothing
        """
        hosts = []
        for host in ips[ip]:
            if host != "[-] No Hostname":
                hosts.append(host)
        return hosts

    def table_section_banner(self):
        """Prints the table section banner."""
        print(colored("Use this section to generate tables of".center(
            60, " "), "grey", "on_yellow"))
        print(colored("ports and services enumerated during testing".center(
            60, " "), "grey", "on_yellow"))
        print()

    def port_count_banner(self):
        """Prints the port count section banner"""
        print(colored("Count of all open ports across all hosts".center(
            60, " "), "grey", "on_yellow"))
        print(colored("enumerated during testing".center(
            60, " "), "grey", "on_yellow"))
        print()

    def header(self, h):
        """Prints a section header"""
        print(colored(f"---{h}---", "magenta"))

    def print_dict(self, d):
        """Prints the contents of the given dictionary (Usually ports)

        Args:
            d: The database containing the port information you want to print

        Returns:
            Nothing
        """
        if not os.path.exists("./output/"):
            os.mkdir("./output/")

        with open('./output/hosts.txt', 'w') as hosts_file:
            for ipaddr in sorted(d.keys()):
                hosts_file.write("="*20 + "\n")
                hosts_file.write(f"[+] {ipaddr}\n")
                hosts_file.write("\n")
                hosts_file.write("---Hostnames---\n")
                hosts = self.get_hostnames(ipaddr)
                if len(hosts) > 0:
                    for host in hosts:
                        hosts_file.write(host + '\n')
                else:
                    hosts_file.write("There are no hostnames\n")
                hosts_file.write("\n")
                hosts_file.write("---Open Ports---\n")
                for i in range(len(d[ipaddr])):
                    self.get_port_details(d[ipaddr][i], hosts_file)
                hosts_file.write('\n')

    def count_open_ports(self, pc):
        """Counts the total number of open ports across all hosts.

        Args:
            pc: The database containing the port count information

        Returns:
            Nothing
        """
        if not quiet:
            self.port_count_banner()
        else:
            print(colored("---Count of All Open Ports---", "magenta"))
        for k in sorted(pc.keys(), key=int):
            print(f"{k} : {pc[k]}")

    def print_ips(self, ip_dict):
        """Prints out the IPs that are listed as UP.
        
        Args:
            ip_dict: The dictionary containing the IP addresses as keys.

        Returns:
            Nothing
        """
        print()
        self.header('List of IPs That Are "UP"')
        for ip in ip_dict.keys():
            print(ip)

    def print_hosts(self, ip_dict):
        """Prints out the full list of enumerated hosts.
        
        Args:
            ip_dict: The dictionary containing the IP addresses as keys.

        Returns:
            Nothing, but prints out all the enumerated hosts across all IPS.
        """
        print()
        self.header('List of All Hosts')
        for ip in ip_dict.keys():
            for host in ip_dict[ip]:
                if host != '':
                    print(host)

    def print_all_services(self, services_dict):
        if not os.path.exists("./output/"):
            os.mkdir("./output/")
        with open('./output/all-services.txt', 'w') as services:
            services.write("---List of All Hosts by Service---\n\n")
            for svc in services_dict.keys():
                services.write(f"=== Service: {svc} ===\n")
                for detail in services_dict[svc]['details']:
                    ip, port, protocol = detail[0], detail[1], detail[2]
                    services.write(f"{ip}:{port}/{protocol}\n")
                services.write("\n\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Make constructing the IP table easy')
    parser.add_argument('-f', '--file', dest='files', nargs='+',
                        required=True, help='The file to parse')
    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                        help='Suppress the welcome banner and headlines')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        help='List all ports with duplicates')
    parser.add_argument('-p', '--ports', dest='ports',
                        action='store_true', help='Show detailed port info')
    parser.add_argument('-d', '--dehashed', dest='dehashed',
                        nargs='+', help='The dehashed JSON file(s) to parse')
    options = parser.parse_args()

    files = options.files
    quiet = options.quiet
    verbose = options.verbose
    show_port_details = options.ports
    dehashed_files = options.dehashed

    base_dir = os.path.dirname(__file__)
    template_file = base_dir + "/Template/appendix.docx"

    ips = {}
    ports = {}
    port_count = {}
    services = {}
    breached_creds = {}
    cred_stuffing = []
    password_spray = []

    for file in files:
        parsed = NParse(file, options)
        parsed.populate_dictionaries(ips, ports, port_count, services)

    if dehashed_files:
        print("[+] Parsing Dehashed file(s)")
        for dehashed_file in dehashed_files:
            parsed_dehashed = ParseDehashed(
                dehashed_file, options=options)
            parsed_dehashed.parse_dehashed_json(
                breached_creds, password_spray, cred_stuffing)

    print(ips)
    print(ports)
    display = DisplayAll(ips, ports, port_count)
    if not quiet:
        display.greeting()
    # Output appendix
    document = Document(template_file)
    appendix = AppendixGenerator(options)
    appendix.export_doc(breached_creds, ips, ports, document)
    display.print_dict(ports)
    display.print_ips(ips)
    display.print_hosts(ips)
    print("[+] Writing listening services CSV file")
    exportCsv(port_count)
    print("[!] Done. Listening Services CSV written to ./output/listening-services.csv")
    print("[+] Writing services file")
    display.print_all_services(services)
    print("[!] Done. Services file written to ./output/all-services.txt")