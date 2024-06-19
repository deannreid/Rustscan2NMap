#!/usr/bin/env python3

# RustScan 2 NMap - Scottish Edition
# Developed by Dean with a bit of love
#
# Script Name: rs2nm.py
#
# Script Information:
# Just a script to save 2 seconds that will automagically grab Rustscan ports and submit them
# to NMAP for some further detailed analysis...
#
# Arguments:
#   - Target
#   - File Save Location
#       - If no location is selected then it will default to the pwd
# python3 rs2nm.py <Target> <FS Location>
#
# Code Version: 1.8.6
#
# Updates:
# 12/05/2024: Initial Code Build
# 18/05/2024: Added Host Discovery Blocker Fix
# 19/05/2024: Added Automatic Domain Append to /etc/hosts
# 15/06/2024: Added HTTP server title check functionality
# 16/06/2024: Added SMB scan functionality with netexec
#             Added SMB port check before running netexec
#             Added domain extraction from netexec output
#             Added pre-installer for dependencies
#             Added rustscan to its own function
#             Added Active Directory enumeration functions
#             Split output for domain information
#             Added enum4linux-ng checks
#             Cleaned up console output and separated tasks
#             Added other modules to enumerate an AD Controller

import subprocess
import sys
import os
import colorama
from colorama import Fore, Style
import re
import ctypes

def print_help():
    print(Fore.CYAN + """
    ==============================================
    RustScan 2 NMap - Scottish Edition
    Developed by Dean with a bit of love

    Script Name: rs2nm.py

    Script Information:

    Just a script to save 2 seconds that will automagically grab Rustscan ports and submit them
    to NMAP for some further detailed analysis...

    Arguments:
      - Target (NO FLAG REQUIRED JUST IP)
      - File Save Location
          - If no location is selected then it will default to the pwd
      - Help: Use '-h' or '--help' to display help information

    Code Version: 1.8.6

    ==============================================
    """ + Style.RESET_ALL)

def check_privileges():
    if os.name == 'nt':
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            print(Fore.RED + "Could not determine admin privileges on Windows: " + str(e) + Style.RESET_ALL)
            sys.exit(1)
        if not is_admin:
            print(Fore.RED + "This script requires administrative privileges. Please run it as an administrator." + Style.RESET_ALL)
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print(Fore.RED + "This script requires sudo privileges. Please run it with sudo." + Style.RESET_ALL)
            sys.exit(1)

def run_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode().strip(), error.decode().strip()

def install_dependency(tool):
    install_commands = {
        "Rustscan": ["cargo", "install", "rustscan"],
        "Netexec": [sys.executable, "-m", "pip", "install", "netexec"],
        "Nmap": ["sudo", "apt-get", "install", "-y", "nmap"],
        "enum4linux-ng": ["sudo", "apt-get", "install", "-y", "enum4linux-ng"],
        "ldap-utils": ["sudo", "apt-get", "install", "-y", "ldap-utils"],
        "BloodHound": ["sudo", "apt-get", "install", "-y", "bloodhound"],
        "Python dependencies": [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
    }

    if tool in install_commands:
        print(Fore.YELLOW + f"Installing {tool}..." + Style.RESET_ALL)
        command = install_commands[tool]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in process.stdout:
            print(Fore.GREEN + line.decode().strip() + Style.RESET_ALL)
        process.wait()
        if process.returncode != 0:
            print(Fore.RED + f"Error installing {tool}" + Style.RESET_ALL)
            sys.exit(1)
        print(Fore.GREEN + f"{tool} installed successfully." + Style.RESET_ALL)

def check_dependencies():
    print(Fore.CYAN + """
    ==========Checking Dependencies==========
    """ + Style.RESET_ALL)

    dependencies = {
        "Rustscan": "rustscan",
        "Netexec": "netexec",
        "Nmap": "nmap",
        "enum4linux-ng": "enum4linux-ng",
        "ldap-utils": "ldapsearch",
        "BloodHound": "bloodhound",
        "Python dependencies": "pip"
    }

    for tool, command in dependencies.items():
        command_check = f"which {command}" if command != "pip" else "pip --version"
        output, error = run_command(command_check.split())

        if "not found" in output or error:
            print(Fore.RED + f"{tool} is not installed. Installing..." + Style.RESET_ALL)
            install_dependency(tool)
        else:
            print(Fore.GREEN + f"{tool} is already installed." + Style.RESET_ALL)

def run_rustscan(target):
    print(Fore.CYAN + """
    ==========Running Rustscan==========
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + f"Target: {Fore.RED + target}" + Style.RESET_ALL)
    print(Fore.YELLOW + "Estimated Time Remaining: 1h 35m\nJust kidding, only going to take a few seconds, they say" + Style.RESET_ALL)

    rustscan_process = subprocess.Popen(["rustscan", "-g", "-a", target, "--ulimit", "70000"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rustscan_output, rustscan_error = rustscan_process.communicate()

    if rustscan_error:
        print(Fore.RED + "\n\nSorry, there appears to be an issue running RustScan:\n" + rustscan_error.decode() + Style.RESET_ALL)
        sys.exit(1)

    open_ports = ""
    for line in rustscan_output.decode().split('\n'):
        if "->" in line:
            open_ports = line.split("->")[1].strip()[1:-1]
            break

    if not open_ports:
        print(Fore.CYAN + "\n\nCanny find anything, tough luck, see you next week." + Style.RESET_ALL)
        sys.exit(0)

    print(Fore.GREEN + "\n\nOoh, there are a few ports open. Gonna copy these to NMAP for you for some intricate scanning...\n(" + Fore.MAGENTA + open_ports + Style.RESET_ALL + ")" + Style.RESET_ALL)
    return open_ports

def run_nmap(nmap_command):
    print(Fore.CYAN + """
    ==========Running Nmap==========
    """ + Style.RESET_ALL)
    nmap_process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    nmap_output, nmap_error = nmap_process.communicate()
    return nmap_output.decode(), nmap_error.decode()

def run_netexec_smb(target_ip, save_location):
    print(Fore.CYAN + """
    ==========Running Netexec SMB==========
    """ + Style.RESET_ALL)
    netexec_output_file = os.path.join(save_location, f"{target_ip}_netexec_smb_results.txt")
    netexec_command = ["netexec", "smb", target_ip]

    with open(netexec_output_file, 'w') as output_file:
        netexec_process = subprocess.Popen(netexec_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        netexec_output, netexec_error = netexec_process.communicate()
        output_file.write(netexec_output.decode())

    if netexec_error:
        print(Fore.RED + "\n\nSorry, there appears to be an issue running Netexec SMB:\n" + netexec_error.decode() + Style.RESET_ALL)
        sys.exit(1)

    print(Fore.GREEN + "I've saved your Netexec SMB loot here: " + netexec_output_file + Style.RESET_ALL)
    return netexec_output.decode()

def run_enum4linux_ng(target_ip, save_location):
    print(Fore.CYAN + """
    ==========Running enum4linux-ng==========
    """ + Style.RESET_ALL)
    enum4linux_output_file = os.path.join(save_location, f"{target_ip}_enum4linux_ng_results.txt")
    enum4linux_command = ["enum4linux-ng", "-A", target_ip]

    with open(enum4linux_output_file, 'w') as output_file:
        enum4linux_process = subprocess.Popen(enum4linux_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        enum4linux_output, enum4linux_error = enum4linux_process.communicate()
        output_file.write(enum4linux_output.decode())

    if enum4linux_error:
        print(Fore.RED + "\n\nSorry, there appears to be an issue running enum4linux-ng:\n" + enum4linux_error.decode() + Style.RESET_ALL)
        sys.exit(1)

    print(Fore.GREEN + "I've saved your enum4linux-ng loot here: " + enum4linux_output_file + Style.RESET_ALL)
    return enum4linux_output.decode()

def run_ldapsearch(target_ip, save_location):
    print(Fore.CYAN + """
    ==========Running ldapsearch==========
    """ + Style.RESET_ALL)
    ldapsearch_output_file = os.path.join(save_location, f"{target_ip}_ldapsearch_results.txt")
    ldapsearch_command = ["ldapsearch", "-x", "-H", f"ldap://{target_ip}", "-s", "sub", "(objectClass=*)"]

    with open(ldapsearch_output_file, 'w') as output_file:
        ldapsearch_process = subprocess.Popen(ldapsearch_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ldapsearch_output, ldapsearch_error = ldapsearch_process.communicate()
        output_file.write(ldapsearch_output.decode())

    if ldapsearch_error:
        print(Fore.RED + "\n\nSorry, there appears to be an issue running ldapsearch:\n" + ldapsearch_error.decode() + Style.RESET_ALL)
        sys.exit(1)

    print(Fore.GREEN + "I've saved your ldapsearch loot here: " + ldapsearch_output_file + Style.RESET_ALL)
    return ldapsearch_output.decode()

def run_bloodhound(target_hostname, save_location, domain, username, password):
    print(Fore.CYAN + """
    ==========Running BloodHound==========
    """ + Style.RESET_ALL)
    bloodhound_output_file = os.path.join(save_location, f"{target_hostname}_bloodhound_results.txt")
    bloodhound_command = ["bloodhound-python", "-d", domain, "-u", username, "-p", password, "-gc", target_hostname, "-c", "All"]

    with open(bloodhound_output_file, 'w') as output_file:
        bloodhound_process = subprocess.Popen(bloodhound_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        bloodhound_output, bloodhound_error = bloodhound_process.communicate()
        output_file.write(bloodhound_output.decode())

    if bloodhound_error:
        print(Fore.MAGENTA + "\n\nBloodhound Output:\n" + Fore.MAGENTA + bloodhound_error.decode() + Style.RESET_ALL)
        sys.exit(1)

    print(Fore.GREEN + "I've saved your BloodHound loot here: " + bloodhound_output_file + Style.RESET_ALL)
    return bloodhound_output.decode()

def add_to_hosts(target_ip, domain):
    hosts_path = r'C:\Windows\System32\drivers\etc\hosts' if os.name == 'nt' else '/etc/hosts'

    try:
        with open(hosts_path, 'a') as hosts_file:
            hosts_file.write(f"{target_ip}\t{domain}\n")
        print(Fore.YELLOW + f"Added {domain} to hosts file with IP {target_ip}" + Style.RESET_ALL)
    except PermissionError:
        print(Fore.RED + "Permission denied: Unable to write to the hosts file. Please run the script as an administrator or with sudo." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"An error occurred while writing to the hosts file: {str(e)}" + Style.RESET_ALL)

def add_domains_to_hosts(nmap_output, netexec_output, target_ip, added_domains):
    print(Fore.CYAN + """
    ==========Checking for domain information==========
    """ + Style.RESET_ALL)

    print(Fore.CYAN + "Checking for domain information from Nmap..." + Style.RESET_ALL)
    found_domain = None
    found_hostname = None

    for line in nmap_output.split('\n'):
        for port in ['389/tcp', '636/tcp', '3268/tcp', '3269/tcp']:
            if port in line and 'open' in line and 'Microsoft Windows Active Directory LDAP' in line:
                print(Fore.CYAN + f"Possible DC Found; Port {port} active with LDAP information:\n" + Fore.GREEN + line + Style.RESET_ALL)
                domain_match = re.search(r'Domain: ([^\s,]+)', line)
                if domain_match:
                    domain = domain_match.group(1).rstrip('.0')
                    if domain not in added_domains:
                        add_to_hosts(target_ip, domain)
                        added_domains.add(domain)
                        found_domain = domain

        if 'Subject Alternative Name' in line and 'DNS:' in line:
            print(Fore.GREEN + "Subject Alternative Name found, extracting DNS information:\n" + line + Style.RESET_ALL)
            san_matches = re.findall(r'DNS:([^,]+)', line)
            for san_domain in san_matches:
                if san_domain not in added_domains:
                    add_to_hosts(target_ip, san_domain)
                    added_domains.add(san_domain)

        if 'Nmap scan report for' in line:
            print(Fore.GREEN + "Extracting hostname from Nmap output:\n" + line + Style.RESET_ALL)
            hostname_match = re.search(r'Nmap scan report for ([^\s]+)', line)
            if hostname_match:
                found_hostname = hostname_match.group(1)

        if '|_http-title: Did not follow redirect to http://' in line:
            print(Fore.GREEN + "HTTP Title indicates a redirect, extracting domain information:\n" + line + Style.RESET_ALL)
            domain_match = re.search(r'http:\/\/([^\/]+)', line)
            if domain_match:
                domain = domain_match.group(1)
                if domain not in added_domains:
                    add_to_hosts(target_ip, domain)
                    added_domains.add(domain)
                    found_domain = domain

        if '|_https-title: Did not follow redirect to https://' in line:
            print(Fore.GREEN + "HTTPS Title indicates a redirect, extracting domain information:\n" + line + Style.RESET_ALL)
            domain_match = re.search(r'https:\/\/([^\/]+)', line)
            if domain_match:
                domain = domain_match.group(1)
                if domain not in added_domains:
                    add_to_hosts(target_ip, domain)
                    added_domains.add(domain)
                    found_domain = domain

    print(Fore.CYAN + "\nChecking for domain information from Netexec..." + Style.RESET_ALL)
    for line in netexec_output.split('\n'):
        if 'SMB' in line and '(domain:' in line:
            print(Fore.GREEN + "\nExtracting domain information from Netexec output:\n" + line + Style.RESET_ALL)
            domain_match = re.search(r'\(domain:([^\)]+)\)', line)
            if domain_match:
                domain = domain_match.group(1)
                if domain not in added_domains:
                    add_to_hosts(target_ip, domain)
                    added_domains.add(domain)
                    found_domain = domain

    return found_domain, found_hostname

def smb_ports_open(open_ports):
    smb_ports = {'445', '137', '138', '139'}
    return any(port in smb_ports for port in open_ports.split(','))

def main():
    try:
        check_privileges()

        if len(sys.argv) > 1 and (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
            print_help()
            sys.exit(0)

        if len(sys.argv) < 2:
            print(Fore.RED + f"Requires: {sys.argv[0]} <Target> [save_location] you dumpling" + Style.RESET_ALL)
            sys.exit(1)

        target = sys.argv[1]
        save_location = os.getcwd() if len(sys.argv) < 3 else sys.argv[2]

        check_dependencies()

        open_ports = run_rustscan(target)

        nmap_output_file = os.path.join(save_location, f"{target}_nmap_results")
        nmap_command = ["nmap", "-p", open_ports, "-sC", "-sV", "-oA", nmap_output_file, target]

        nmap_output, nmap_error = run_nmap(nmap_command)
        if "Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn" in nmap_output:
            print(Fore.RED + "\nHost seems down or is blocking ping probes. Retrying without Host Discovery..." + Style.RESET_ALL)
            nmap_command.insert(1, "-Pn")
            nmap_output, nmap_error = run_nmap(nmap_command)

        if nmap_error:
            print(Fore.RED + "\n\nSorry, there appears to be an issue running NMap:" + nmap_error + Style.RESET_ALL)
            sys.exit(1)

        print(nmap_output)
        print(Fore.GREEN + "I've saved your loot here: " + nmap_output_file + Style.RESET_ALL)

        added_domains = set()

        netexec_output = ""
        if smb_ports_open(open_ports):
            netexec_output = run_netexec_smb(target, save_location)

        enum4linux_ng_output = run_enum4linux_ng(target, save_location)
        ldapsearch_output = run_ldapsearch(target, save_location)

        # Extract domain and hostname from Nmap output for BloodHound
        domain, hostname = add_domains_to_hosts(nmap_output, netexec_output, target, added_domains)

        # BloodHound credentials prompt
        if domain and hostname:
            username = input(Fore.YELLOW + "Enter username for BloodHound: " + Style.RESET_ALL)
            password = input(Fore.YELLOW + "Enter password for BloodHound: " + Style.RESET_ALL)

            if username and password:
                bloodhound_output = run_bloodhound(hostname, save_location, domain, username, password)
                print(bloodhound_output)
            else:
                print(Fore.CYAN + "Skipping BloodHound enumeration due to missing credentials." + Style.RESET_ALL)
        else:
            print(Fore.CYAN + "Skipping BloodHound enumeration due to missing domain or hostname information." + Style.RESET_ALL)

        print(enum4linux_ng_output)
        print(ldapsearch_output)
        print(Fore.GREEN + "I've saved your Active Directory enumeration results here: " + save_location + Style.RESET_ALL)

    except KeyboardInterrupt:
        while True:
            confirmation = input(Fore.YELLOW + "\n\nAre you sure you want to exit? (k/n): " + Style.RESET_ALL)
            if confirmation.lower() == 'k':
                print(Fore.RED + "\n\nNobody likes you anyway..." + Style.RESET_ALL)
                sys.exit(0)
            elif confirmation.lower() == 'n':
                print(Fore.YELLOW + "\n\nMore? Well I'm quitting anyway\n Just press the up arrow and don't CTRL+C again ¬_¬" + Style.RESET_ALL)
                sys.exit(0)
            elif confirmation.lower() == 'y':
                print(Fore.YELLOW + "\n\nMaybe you should read the instructions... \n Exiting...." + Style.RESET_ALL)
                sys.exit(0)
            else:
                print(Fore.RED + "\n\nInvalid input. Please enter 'k' or 'n'." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
