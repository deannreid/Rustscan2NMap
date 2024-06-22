#!/usr/bin/env python3

# RustScan 2 NMap - Scottish Edition
# Developed by Dean with a bit of love
#
# Script Name: rs2nm.py
#
# Script Information:
# Just a script to save 2 seconds that will automagically grab Rustscan ports and submit them to NMAP for some further detailed analysis...
#
# Arguments:
#   - Target
#   - File Save Location
#       - If no location is selected then it will default to the pwd
#   '-b', '-B', '--Bloodhound' -- Activate BloodHound scan
#   '-v', '-V', '--version'    -- Show Version Info
# python3 rs2nm.py <Target> <FS Location>
#
# Code Version: 1.9
#
# Updates:
# 12/05/2024: Initial Code Build
#             Who Doesn't Like Colours'
#             Added Help Bit just in case
# 18/05/2024: Added Host Discovery Blocker Fix
# 19/05/2024: Added Automatic Domain Append to /etc/hosts
#             Improved Domain Extraction with Regular Expressions
# 20/06/2024: Added MultiOS Support - Win/Linux/Mac
# 22/06/2024: Refined a few things, added config and seperated install to new file

import subprocess
import sys
import os
import platform
import json
import random
import re
from colorama import Fore, Style
import ctypes
import argparse

CONFIG_FILE = "~/.rs2nm/config.json"

def is_admin():
    if platform.system().lower() == "windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            print_message("Could not determine admin privileges on Windows: " + str(e), "error")
            sys.exit(1)
    elif platform.system().lower() in ["linux", "darwin"]:
        return os.geteuid() == 0
    else:
        return False

def check_python_version():
    python_version = sys.version.split()[0]
    print_message(f"Python Version Detected: {python_version}", "info")
    if sys.version_info < (3, 10):
        print_message("This script requires Python 3.10.0 or higher. Please upgrade your Python version.", "error")
        sys.exit(1)

def run_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode().strip(), error.decode().strip()

def load_skipped_dependencies():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            return json.load(file)
    return []

def save_skipped_dependencies(skipped_dependencies):
    with open(CONFIG_FILE, "w") as file:
        json.dump(skipped_dependencies, file)

def install_dependency(tool):
    install_commands = {
        "Rustscan": {
            "linux": ["cargo", "install", "rustscan"],
            "windows": [sys.executable, "-m", "pip", "install", "rustscan"],
            "darwin": ["cargo", "install", "rustscan"]
        },
        "Netexec": {
            "linux": [sys.executable, "-m", "pip", "install", "netexec"],
            "windows": [sys.executable, "-m", "pip", "install", "netexec"],
            "darwin": [sys.executable, "-m", "pip", "install", "netexec"]
        },
        "Nmap": {
            "linux": ["sudo", "apt-get", "install", "-y", "nmap"],
            "windows": ["choco", "install", "nmap"],
            "darwin": ["brew", "install", "nmap"]
        },
        "enum4linux-ng": {
            "linux": ["sudo", "apt-get", "install", "-y", "enum4linux-ng"],
            "windows": [sys.executable, "-m", "pip", "install", "enum4linux-ng"],
            "darwin": ["brew", "install", "enum4linux-ng"]
        },
        "ldap-utils": {
            "linux": ["sudo", "apt-get", "install", "-y", "ldap-utils"],
            "windows": [sys.executable, "-m", "pip", "install", "ldap3"],
            "darwin": ["brew", "install", "ldap-utils"]
        },
        "BloodHound": {
            "linux": ["sudo", "apt-get", "install", "-y", "bloodhound"],
            "windows": ["choco", "install", "bloodhound"],
            "darwin": ["brew", "install", "bloodhound"]
        },
        "Python dependencies": {
            "linux": [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            "windows": [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            "darwin": [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
        }
    }

    system = platform.system().lower()
    if tool in install_commands and system in install_commands[tool]:
        print_message(f"Installing {tool}...", "info")
        command = install_commands[tool][system]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in process.stdout:
            print_message(line.decode().strip(), "success")
        process.wait()
        if process.returncode != 0:
            print_message(f"Error installing {tool}", "error")
            sys.exit(1)
        print_message(f"{tool} installed successfully.", "success")

def print_message(message, msg_type):
    symbols = {
        "info": Fore.CYAN + "{~} ",
        "warning": Fore.RED + "{!} ",
        "success": Fore.GREEN + "{✓} ",
        "error": Fore.RED + "{!} ",
        "disabled": Fore.LIGHTBLACK_EX + "{X} "
    }
    print(symbols.get(msg_type, "") + message + Style.RESET_ALL)

def print_ascii_banner():
    print(Fore.CYAN + """
_|_|_|      _|_|_|        _|_|        _|      _|  _|      _|
_|    _|  _|            _|    _|      _|_|    _|  _|_|  _|_|
_|_|_|      _|_|            _|        _|  _|  _|  _|  _|  _|
_|    _|        _|        _|          _|    _|_|  _|      _|
_|    _|  _|_|_|        _|_|_|_|      _|      _|  _|      _|

The soon to be all in one pentest enumeration tool.

------------------------------------------------
::        %INSERT RELEVANT DISCORD HERE       ::
:: https://github.com/deannreid/Rustscan2NMap ::
------------------------------------------------ """ + Style.RESET_ALL)

def print_blurb():
    blurbs = [
        "Enumerating services: Like snooping through your neighbor's Wi-Fi, but legal.\n",
        "Exploring services: The geek's way of saying 'I'm just curious!'\n",
        "Discovering endpoints: Like a treasure hunt, but with more IP addresses.\n",
        "Probing the depths: Finding the juicy bits your network's been hiding.\n"
    ]
    print(random.choice(blurbs))

def check_config_file_exists():
    if os.path.exists(CONFIG_FILE):
        print_message(f"Configuration file found: {CONFIG_FILE}", "info")
    else:
        print_message(f"Configuration file not found: {CONFIG_FILE}", "warning")

def print_version():
    print(Fore.CYAN + """
    ==============================================
    | RustScan 2 NMap - Scottish Edition          |
    | Version: 1.9.5                              |
    |                                             |
    | Developed by Dean with a bit of love        |
    ==============================================
    | Script Information:                         |
    | Just a script to save 2 seconds that will   |
    | automagically grab Rustscan ports and       |
    | submit them to NMAP for some further        |
    | detailed analysis...                        |
    ==============================================
    | Updates:                                    |
    | 12/05/2024: Initial Code Build              |
    | 18/05/2024: Added Host Discovery Blocker Fix|
    | 19/05/2024: Added Automatic Domain Append   |
    |             to /etc/hosts                   |
    | 15/06/2024: Added HTTP server title check   |
    |             functionality                   |
    | 16/06/2024: Added SMB scan functionality    |
    |             with netexec                    |
    | 20/06/2024: Updated script to check for     |
    |             hostnames and prompt user for   |
    |             target choice                   |
    | 22/06/2024: Added version flag              |
    ==============================================
    """ + Style.RESET_ALL)

def run_rustscan(target):
    print_message(f"Target: {target}", "success")
    print_message("Running Rustscan", "info")
    print_message("Estimated Time Remaining: 1h 35m\nJust kidding, only going to take a few seconds, they say\n", "info")

    rustscan_process = subprocess.Popen(["rustscan", "-g", "-a", target, "--ulimit", "70000"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rustscan_output, rustscan_error = rustscan_process.communicate()

    if rustscan_error:
        print_message("Sorry, there appears to be an issue running RustScan:\n" + rustscan_error.decode(), "error")
        sys.exit(1)

    open_ports = ""
    for line in rustscan_output.decode().split('\n'):
        if "->" in line:
            open_ports = line.split("->")[1].strip()[1:-1]
            break

    if not open_ports:
        print_message("Canny find anything, tough luck, see you next week.", "info")
        sys.exit(0)

    print_message(f"Ooh, there are a few ports open. Gonna copy these to NMAP for you for some intricate scanning...\nPorts Open: ({open_ports})\n", "success")
    return open_ports

def run_nmap(nmap_command):
    print_message("Running Nmap", "info")
    print_message("This can take a few moments depending on how many ports are available\n", "info")
    nmap_process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    nmap_output, nmap_error = nmap_process.communicate()
    return nmap_output.decode(), nmap_error.decode()

def run_netexec_smb(target_ip, save_location):
    print_message("Running Netexec SMB", "info")
    netexec_output_file = os.path.join(save_location, f"{target_ip}_netexec_smb_results.txt")
    netexec_command = ["netexec", "smb", target_ip]

    with open(netexec_output_file, 'w') as output_file:
        netexec_process = subprocess.Popen(netexec_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        netexec_output, netexec_error = netexec_process.communicate()
        output_file.write(netexec_output.decode())

    if netexec_error:
        print_message("Sorry, there appears to be an issue running Netexec SMB:\n" + netexec_error.decode(), "error")
        sys.exit(1)

    print_message(f"I've saved your Netexec SMB loot here: {netexec_output_file}", "success")
    return netexec_output.decode()

def run_enum4linux_ng(target_ip, save_location):
    print_message("Running enum4linux-ng", "info")
    enum4linux_output_file = os.path.join(save_location, f"{target_ip}_enum4linux_ng_results.txt")
    enum4linux_command = ["enum4linux-ng", "-A", target_ip]

    with open(enum4linux_output_file, 'w') as output_file:
        enum4linux_process = subprocess.Popen(enum4linux_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        enum4linux_output, enum4linux_error = enum4linux_process.communicate()
        output_file.write(enum4linux_output.decode())

    if enum4linux_error:
        print_message("Sorry, there appears to be an issue running enum4linux-ng:\n" + enum4linux_error.decode(), "error")
        sys.exit(1)

    print_message(f"I've saved your enum4linux-ng loot here: {enum4linux_output_file}", "success")
    return enum4linux_output.decode()

def run_ldapsearch(target_ip, save_location):
    print_message("Running ldapsearch", "info")
    ldapsearch_output_file = os.path.join(save_location, f"{target_ip}_ldapsearch_results.txt")
    ldapsearch_command = ["ldapsearch", "-x", "-H", f"ldap://{target_ip}", "-s", "sub", "(objectClass=*)"]

    with open(ldapsearch_output_file, 'w') as output_file:
        ldapsearch_process = subprocess.Popen(ldapsearch_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ldapsearch_output, ldapsearch_error = ldapsearch_process.communicate()
        output_file.write(ldapsearch_output.decode())

    if ldapsearch_error:
        print_message("Sorry, there appears to be an issue running ldapsearch:\n" + ldapsearch_error.decode(), "error")
        sys.exit(1)

    print_message(f"I've saved your ldapsearch loot here: {ldapsearch_output_file}", "success")
    return ldapsearch_output.decode()

def run_bloodhound(target_hostname, save_location, domain, username, password):
    print_message("Running BloodHound", "info")
    print_message("Warning: BloodHound can be noisy and is suggested not to be used in production environments.", "warning")
    bloodhound_output_file = os.path.join(save_location, f"{target_hostname}_bloodhound_results.txt")
    bloodhound_command = ["bloodhound-python", "-d", domain, "-u", username, "-p", password, "-gc", target_hostname, "-c", "All"]

    with open(bloodhound_output_file, 'w') as output_file:
        bloodhound_process = subprocess.Popen(bloodhound_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        bloodhound_output, bloodhound_error = bloodhound_process.communicate()
        output_file.write(bloodhound_output.decode())

    if bloodhound_error:
        print_message("Bloodhound Output:\n" + bloodhound_error.decode(), "error")
        sys.exit(1)

    print_message(f"I've saved your BloodHound loot here: {bloodhound_output_file}", "success")
    return bloodhound_output.decode()

def add_to_hosts(target_ip, domain):
    hosts_path = r'C:\Windows\System32\drivers\etc\hosts' if os.name == 'nt' else '/etc/hosts'

    try:
        with open(hosts_path, 'a') as hosts_file:
            hosts_file.write(f"{target_ip}\t{domain}\n")
        print_message(f"Added {domain} to hosts file with IP {target_ip}", "success")
    except PermissionError:
        print_message("Permission denied: Unable to write to the hosts file. Please run the script as an administrator or with sudo.", "error")
    except Exception as e:
        print_message(f"An error occurred while writing to the hosts file: {str(e)}", "error")

def get_domains_from_nmap(nmap_output):
    print_message("Checking for domain information", "info")

    domains = set()

    for line in nmap_output.split('\n'):
        for port in ['389/tcp', '636/tcp', '3268/tcp', '3269/tcp']:
            if port in line and 'open' in line and 'Microsoft Windows Active Directory LDAP' in line:
                print_message(f"Possible DC Found; Port {port} active with LDAP information:\n" + line, "info")
                domain_match = re.search(r'Domain: ([^\s,]+)', line)
                if domain_match:
                    domains.add(domain_match.group(1).rstrip('.0'))

        if 'Subject Alternative Name' in line and 'DNS:' in line:
            print_message("Subject Alternative Name found, extracting DNS information:\n" + line, "info")
            san_matches = re.findall(r'DNS:([^,]+)', line)
            domains.update(san_matches)

        if 'Nmap scan report for' in line:
            print_message("Extracting hostname from Nmap output:\n" + line, "info")
            hostname_match = re.search(r'Nmap scan report for ([^\s]+)', line)
            if hostname_match:
                domains.add(hostname_match.group(1))

        if '|_http-title: Did not follow redirect to http://' in line:
            print_message("HTTP Title indicates a redirect, extracting domain information:\n" + line, "info")
            domain_match = re.search(r'http:\/\/([^\/]+)', line)
            if domain_match:
                domains.add(domain_match.group(1))

        if '|_https-title: Did not follow redirect to https://' in line:
            print_message("HTTPS Title indicates a redirect, extracting domain information:\n" + line, "info")
            domain_match = re.search(r'https:\/\/([^\/]+)', line)
            if domain_match:
                domains.add(domain_match.group(1))

    return list(domains)

def smb_ports_open(open_ports):
    smb_ports = {'445', '137', '138', '139'}
    return any(port in smb_ports for port in open_ports.split(','))

def main():
    try:
        is_admin()

        parser = argparse.ArgumentParser(description='RustScan 2 NMap - Scottish Edition')
        parser.add_argument('target', help='Target IP address')
        parser.add_argument('save_location', nargs='?', default=os.getcwd(), help='File Save Location (defaults to current directory)')
        parser.add_argument('-b', '-B', '--Bloodhound', action='store_true', help='Activate BloodHound scan')
        parser.add_argument('-v', '--version', action='store_true', help='Display the version of the script')
        args = parser.parse_args()

        if args.version:
            print_version()
            sys.exit(0)

        target = args.target
        save_location = args.save_location
        activate_bloodhound = args.Bloodhound

        check_config_file_exists()

        open_ports = run_rustscan(target)

        nmap_output_file = os.path.join(save_location, f"{target}_nmap_results")
        nmap_command = ["nmap", "-p", open_ports, "-sC", "-sV", "-oA", nmap_output_file, target]

        nmap_output, nmap_error = run_nmap(nmap_command)
        if "Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn" in nmap_output:
            print_message("Host seems down or is blocking ping probes. Retrying without Host Discovery...", "error")
            nmap_command.insert(1, "-Pn")
            nmap_output, nmap_error = run_nmap(nmap_command)

        if nmap_error:
            print_message("Sorry, there appears to be an issue running NMap:" + nmap_error, "error")
            sys.exit(1)

        print(nmap_output)
        print_message(f"I've saved your loot here: {nmap_output_file}", "success")

        # Extract domain information from Nmap output
        domains = get_domains_from_nmap(nmap_output)

        # Add domains to hosts file
        for domain in domains:
            add_to_hosts(target, domain)

        # Prompt user to choose between hostname or IP if a domain is found
        if domains and len(domains) > 1:
            while True:
                choice = input(Fore.YELLOW + f"\nFound domains: {', '.join(domains)}. Do you want to target one of these domains? (y/n): " + Style.RESET_ALL)
                if choice.lower() == 'y':
                    print_message("Select the domain you want to target:", "info")
                    for i, domain in enumerate(domains):
                        print_message(f"{i + 1}: {domain}", "info")
                    selected_index = input(Fore.YELLOW + "Enter the number corresponding to the domain: " + Style.RESET_ALL)
                    if selected_index.isdigit() and 1 <= int(selected_index) <= len(domains):
                        target = domains[int(selected_index) - 1]
                        print_message(f"Targeting domain: {target}", "success")
                        break
                    else:
                        print_message("Invalid input. Please enter a valid number.", "error")
                elif choice.lower() == 'n':
                    print_message(f"Continuing with IP: {target}", "success")
                    break
                else:
                    print_message("Invalid input. Please enter 'y' or 'n'.", "error")

        # Run all scans using the selected target
        if smb_ports_open(open_ports):
            netexec_output = run_netexec_smb(target, save_location)

        enum4linux_ng_output = run_enum4linux_ng(target, save_location)
        ldapsearch_output = run_ldapsearch(target, save_location)

        # BloodHound scan if activated
        if activate_bloodhound:
            if domains:
                username = input(Fore.YELLOW + "Enter username for BloodHound: " + Style.RESET_ALL)
                password = input(Fore.YELLOW + "Enter password for BloodHound: " + Style.RESET_ALL)

                if username and password:
                    bloodhound_output = run_bloodhound(target, save_location, domains[0], username, password)
                    print(bloodhound_output)
                else:
                    print_message("Skipping BloodHound enumeration due to missing credentials.", "info")
            else:
                print_message("Skipping BloodHound enumeration due to missing domain or hostname information.", "info")

        print(enum4linux_ng_output)
        print(ldapsearch_output)
        print_message(f"I've saved your Active Directory enumeration results here: {save_location}", "success")

    except KeyboardInterrupt:
        while True:
            confirmation = input(Fore.YELLOW + "\n\nAre you sure you want to exit? (k/n): " + Style.RESET_ALL)
            if confirmation.lower() == 'k':
                print_message("Nobody likes you anyway...", "error")
                sys.exit(0)
            elif confirmation.lower() == 'n':
                print_message("More? Well I'm quitting anyway\n Just press the up arrow and don't CTRL+C again ¬_¬", "warning")
                sys.exit(0)
            elif confirmation.lower() == 'y':
                print_message("Maybe you should read the instructions... \n Exiting....", "info")
                sys.exit(0)
            else:
                print_message("Invalid input. Please enter 'k' or 'n'.", "error")

if __name__ == "__main__":
    print_ascii_banner()
    print_blurb()

    check_python_version()

    if not is_admin():
        print_message("This script requires administrative privileges. Please run it as an administrator or with sudo.", "error")
        sys.exit(1)

    system = platform.system().lower()
    print_message(f"Operating System Detected: {platform.system()}", "info")

    main()
