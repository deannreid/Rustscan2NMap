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
# python3 rs2nm.py <Target> <FS Location>
#
# Code Version: 1.1
#
# Updates:
# 12/05/2024: Initial Code Build
#             Who Doesn't Like Colours'
#             Added Help Bit just in case
# 18/05/2024: Added Host Discovery Blocker Fix
# 19/05/2024: Added Automatic Domain Append to /etc/hosts
#             Improved Domain Extraction with Regular Expressions
# 20/05/2024: Added MultiOS Support - Win/Linux
#             Added Admin/Sudo Check to for adding to host file
#

import subprocess
import sys
import os
import colorama
from colorama import Fore, Style
import re
import ctypes

def print_help():
    print("""
    RustScan 2 NMap - Scottish Edition
    Developed by Dean with a bit of love

    Script Name: rs2nm.py

    Script Information:
    Just a script to save 2 seconds that will automagically grab Rustscan ports and submit them to NMAP for some further detailed analysis...

    Arguments:
      - Target (NO FLAG REQUIRED JUST IP)
      - File Save Location
          - If no location is selected then it will default to the pwd
      - Help: Use '-h' or '--help' to display help information
          
    """)

def rootChecker():
    if os.name == 'nt':
        # Check for admin privileges on Windows
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            print(Fore.RED + "Could not determine admin privileges on Windows: " + str(e) + Style.RESET_ALL)
            sys.exit(1)
        if not is_admin:
            print(Fore.RED + "This script requires administrative privileges. Please run it as an administrator." + Style.RESET_ALL)
            sys.exit(1)
    else:
        # Check for sudo on Linux
        if os.geteuid() != 0:
            print(Fore.RED + "This script requires sudo privileges. Please run it with sudo." + Style.RESET_ALL)
            sys.exit(1)

def run_nmap(nmap_command):
    nmap_process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    nmap_output, nmap_error = nmap_process.communicate()
    return nmap_output.decode(), nmap_error.decode()

def add2Hosts(nmap_output, target_ip):
    print(Fore.CYAN + "Checking for open Active Directory ports and extracting domain information..." + Style.RESET_ALL)
    for line in nmap_output.split('\n'):
        if any(port in line for port in ['389/tcp', '636/tcp', '3268/tcp', '3269/tcp']) and 'open' in line and 'Microsoft Windows Active Directory LDAP' in line:
            print(Fore.GREEN + "Active Directory LDAP information found:\n" + line + Style.RESET_ALL)
            # Extract domain from the line using regular expressions
            domain_match = re.search(r'Domain: ([^\s,]+)', line)
            if domain_match:
                domain = domain_match.group(1).rstrip('.0')
                print(Fore.GREEN + f"Extracted domain: {domain}" + Style.RESET_ALL)
                with open('/etc/hosts', 'a') as hosts_file:
                    hosts_file.write(f"{target_ip}\t{domain}\n")
                print(Fore.GREEN + f"Added {domain} to the host file with IP {target_ip}" + Style.RESET_ALL)
                return
    print(Fore.RED + "No relevant domain information found for any Active Directory ports." + Style.RESET_ALL)

def main():
    try:
        rootChecker()

        # --help Argument
        if len(sys.argv) > 1 and (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
            print_help()
            sys.exit(0)

        # Check target is provided
        if len(sys.argv) < 7:
            print(Fore.RED + f"Requires: {sys.argv[0]} <Target> [save_location] you dumpling" + Style.RESET_ALL)
            sys.exit(1)

        target = sys.argv[1]
        save_location = os.getcwd() if len(sys.argv) < 3 else sys.argv[2]

        print(Fore.YELLOW + "Just gonnae run a quick wee rustscan test\nYou selected: " + Fore.RED + target + Style.RESET_ALL)
        print(Fore.YELLOW + "Estimated Time Remaining: 1h 35m...\nJust kidding, only going to take a few seconds, they say" + Style.RESET_ALL)

        rustscan_process = subprocess.Popen(["rustscan", "-g", "-a", target, "--ulimit", "10000"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rustscan_output, rustscan_error = rustscan_process.communicate()

        if rustscan_error:
            print(Fore.RED + "\n\nExcuse me pal\n Someone(probably dean) fucked up because I canny run RustScan:\n" + rustscan_error.decode() + Style.RESET_ALL)
            sys.exit(1)

        # Extract ports
        open_ports = ""
        for line in rustscan_output.decode().split('\n'):
            if "->" in line:
                open_ports = line.split("->")[1].strip()[1:-1]
                break

        if not open_ports:
            print(Fore.CYAN + "\n\nCanny find anything, tough luck, see you next week." + Style.RESET_ALL)
            sys.exit(0)

        print(Fore.GREEN + "\n\nOOoh, There are a few ports open \nGonnae copy these to NMAP for ye, for some intricate.... ;)  scanning...\n(" + Fore.MAGENTA + open_ports + Style.RESET_ALL + ")" + Style.RESET_ALL)

        nmap_output_file = os.path.join(save_location, f"{target}_nmap_results")
        nmap_command = ["nmap", "-p", open_ports, "-sC", "-sV", "-oA", nmap_output_file, target]

        nmap_output, nmap_error = run_nmap(nmap_command)
        if "Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn" in nmap_output:
            print(Fore.RED + "\nHost seems down or is blocking ping probes. Retrying without Host Discovery..." + Style.RESET_ALL)
            nmap_command.insert(1, "-Pn")
            nmap_output, nmap_error = run_nmap(nmap_command)

        if nmap_error:
            print(Fore.RED + "\n\nExcuse me pal\n Someone(probably dean) fucked up because I canny run NMap:" + nmap_error + Style.RESET_ALL)
            sys.exit(1)

        print(nmap_output)
        print(Fore.GREEN + "I've saved your loot here: " + nmap_output_file + Style.RESET_ALL)

        add2Hosts(nmap_output, target)

    except KeyboardInterrupt:
        while True:
            confirmation = input(Fore.YELLOW + "\n\nAre you sure you want to exit? (k/n): " + Style.RESET_ALL)
            if confirmation.lower() == 'k':
                print(Fore.RED + "\n\nNobody Likes you anyway..." + Style.RESET_ALL)
                sys.exit(0)
            elif confirmation.lower() == 'n':
                print(Fore.YELLOW + "\n\nMore? Well I'm Quitting anyway\n Just Press the Up Arrow and don't CTRL+C again ¬_¬" + Style.RESET_ALL)
                sys.exit(0)
            elif confirmation.lower() == 'y':
                print(Fore.YELLOW + "\n\nMaybe you should read the instructions... \n Exiting...." + Style.RESET_ALL)
                sys.exit(0)
            else:
                print(Fore.RED + "\n\nInvalid input. Please enter 'k' or 'n'." + Style.RESET_ALL)

if __name__ == "__main__":
    main()