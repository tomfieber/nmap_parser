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

    def populate_dictionaries(self, ips, pd, pc):
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
                hostname = "[-] No Hostname"
            if ip not in ips.keys():
                ips[ip] = [hostname]
            else:
                ips[ip].append(hostname)

            # Get a dictionary object of all service details
            for service in host.services:

                svcDetails = service.get_dict()
                svcPort = svcDetails['port']
                svcState = svcDetails['state']

                port_is_open = self.check_open(svcState)

                if port_is_open:

                    # Get a count of all ports across hosts
                    if svcPort not in pc.keys():
                        pc[svcPort] = 1
                    else:
                        pc[svcPort] += 1

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

    def get_port_details(self, dict):
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
        print(colored(f'[*] {port}', 'blue', attrs=['bold']), end=" ")
        print(protocol, end=" ")
        print(service)
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
        for host in ips[ip]:
            print(colored(host, "green"))

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
        if not quiet:
            self.table_section_banner()
        else:
            print()
        for ipaddr in sorted(d.keys()):
            print(colored(f"[+] {ipaddr}", "yellow", attrs=['bold']))
            print()
            self.header("Hostnames")
            self.get_hostnames(ipaddr)
            print()
            self.header("Open Ports")
            for i in range(len(d[ipaddr])):
                self.get_port_details(d[ipaddr][i])
            print()

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
                if host != '[-] No Hostname':
                    print(host)


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
    options = parser.parse_args()

    files = options.files
    quiet = options.quiet
    verbose = options.verbose
    show_port_details = options.ports

    ips = {}
    ports = {}
    port_count = {}

    for file in files:
        parsed = NParse(file, options)
        parsed.populate_dictionaries(ips, ports, port_count)

    display = DisplayAll(ips, ports, port_count)
    if not quiet:
        display.greeting()
    display.print_dict(ports)
    display.count_open_ports(port_count)