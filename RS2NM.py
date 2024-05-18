#!/usr/bin/env python3

# RustScan 2 NMap - Scottish Edition
# Developed by Dean with a bit of love
#
# Script Name: rs2nm.py
#
# Script Information:
#
# Just a script to save 2 seconds that will automagically grab Rustscan ports and submit them
# to NMAP for some further detailed anal.lysis...
#
# Arguments:
#   - Target
#   - File Save Location
#       - If no location is selected then it will default to the pwd
# python3 rs2nm.py <Target> <FS Location>

# Code Version: 1.0
#
# Updates:
# 12/05/2024: Initial Code Build
#             Who Doesn't Like Colours'
#             Added Help Bit just in case
#

import subprocess
import sys
import os
import colorama
from colorama import Fore, Style

def print_help():
    print("""
    RustScan 2 NMap - Scottish Edition
    Developed by Dean with a bit of love

    Script Name: rs2nm.py

    Script Information:

    Just a script to save 2 seconds that will automagically grab Rustscan ports and submit them
    to NMAP for some further detailed anal.lysis...

    Arguments:
      - Target (NO FLAG REQUIRED JUST IP)
      - File Save Location
          - If no location is selected then it will default to the pwd
      - Help: Use '-h' or '--help' to display help information

    Code Version: 1.1

    Updates:
    12/05/2024: Initial Code Build
                Who Doesn't Like Colours'
                Added Help Bit just in case
    """)

def run_nmap(nmap_command):
    nmap_process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    nmap_output, nmap_error = nmap_process.communicate()
    return nmap_output.decode(), nmap_error.decode()

def main():
    try:
        # Check if help argument is provided
        if len(sys.argv) > 1 and (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
            print_help()
            sys.exit(0)

        # Check target is provided
        if len(sys.argv) < 2:
            print(Fore.RED + "Requires: {} <Target> [save_location] you dumpling".format(sys.argv[0]) + Style.RESET_ALL)
            sys.exit(1)

        # Assign the The_Bad_Guy from the argument
        The_Bad_Guy = sys.argv[1]

        # Set the default output directory to current directory if not provided
        save_location = os.getcwd() if len(sys.argv) < 3 else sys.argv[2]

        print(Fore.YELLOW + "Just gonnae run a quick wee rustscan test\nYou selected: {}".format(Fore.RED + The_Bad_Guy + Style.RESET_ALL))
        print(Fore.YELLOW + "Estimated Time Remaining: 1h 35m\n\nJust kidding, only going to take a few seconds, they say" + Style.RESET_ALL)

        # Find open ports
        rustscan_process = subprocess.Popen(["rustscan", "-g", "-a", The_Bad_Guy, "--ulimit", "5000"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rustscan_output, rustscan_error = rustscan_process.communicate()

        if rustscan_error:
            print(Fore.RED + "\n\nExcuse me pal\n Someone(probably dean) fucked up because I canny run RustScan:\n", rustscan_error.decode()+Style.RESET_ALL)
            sys.exit(1)

        # Extract ports
        open_ports = ""
        for line in rustscan_output.decode().split('\n'):
            if "->" in line:
                open_ports = line.split("->")[1].strip()[1:-1]
                break

        if not open_ports:
            print(Fore.CYAN + "\n\nCanny find anything, tough luck, see you next week."+Style.RESET_ALL)
            sys.exit(0)

        print(Fore.GREEN + "\n\nOOoh, There are a few ports open \nGonnae copy these to NMAP for ye, for some intricate.... ;)  scanning...\n({})".format(Fore.MAGENTA + open_ports + Style.RESET_ALL) + Style.RESET_ALL)

        # Run Nmap

  # Run Nmap
        nmap_output_file = os.path.join(save_location, "{}_nmap_results".format(The_Bad_Guy))
        nmap_command = ["nmap", "-p", open_ports, "-sC", "-sV", "-oA", nmap_output_file, The_Bad_Guy]

        nmap_output, nmap_error = run_nmap(nmap_command)
        if "Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn" in nmap_output:
            print(Fore.RED + "\nHost seems down or is blocking ping probes. Retrying without Host Discovery..." + Style.RESET_ALL)
            nmap_command.insert(1, "-Pn")
            nmap_output, nmap_error = run_nmap(nmap_command)

        if nmap_error:
            print(Fore.RED + "\n\nExcuse me pal\n Someone(probably dean) fucked up because I canny run NMap:", nmap_error + Style.RESET_ALL)
            sys.exit(1)

        print(nmap_output)
        print(Fore.GREEN + "I've saved your loot here:", nmap_output_file + Style.RESET_ALL)

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
                print(Fore.RED + "\n\nInvalid input. Please enter 'y' or 'n'." + Style.RESET_ALL)
                continue
if __name__ == "__main__":
    main()
