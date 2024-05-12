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
# python3 rs2nm.py <Target> <FS Location>

# Code Version: 1.0
#
# Updates:
# 12/05/2024: Initial Code Build
#
#

import subprocess
import sys
import os

def main():
    # Check target is provided
    if len(sys.argv) < 2:
        print("Requires: {} <Target> [save_location] you dumpling".format(sys.argv[0]))
        sys.exit(1)

    # Assign the The_Bad_Guy from the argument
    The_Bad_Guy = sys.argv[1]

    # Set the default output directory to current directory if not provided
    save_location = os.getcwd() if len(sys.argv) < 3 else sys.argv[2]

    print("Just gonnae run a quick wee rustscan test \n You Selected: {}...\n Estimated Time Remaining: 1h 35m\n\n Just Kidding, only going to take a few seconds, they say".format(The_Bad_Guy))

    # Find open ports
    rustscan_process = subprocess.Popen(["rustscan", "-g", "-a", The_Bad_Guy, "--ulimit", "5000"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rustscan_output, rustscan_error = rustscan_process.communicate()

    if rustscan_error:
        print("\n\nExcuse me Pal\n Someone(probably dean) Fucked up because I Canny run RustScan:\n", rustscan_error.decode())
        sys.exit(1)

    # Extract ports
    open_ports = ""
    for line in rustscan_output.decode().split('\n'):
        if "->" in line:
            open_ports = line.split("->")[1].strip()[1:-1]
            break

    if not open_ports:
        print("\n\nCanny find anything, tough luck, see you next week.")
        sys.exit(0)

    print("\n\nOOoh, There are a few ports open \n Gonnae copy these to NMAP for ye, for some intricate.... ;)  scanning... \n ({})".format(open_ports))

    # Run Nmap
    nmap_output_file = os.path.join(save_location, "{}_nmap_results".format(The_Bad_Guy))
    nmap_process = subprocess.Popen(["nmap", "-sC", "-sV", "-oA", nmap_output_file, "-p", open_ports, The_Bad_Guy], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    nmap_output, nmap_error = nmap_process.communicate()

    if nmap_error:
        print("\n\nExcuse me Pal\n Someone(probably dean) Fucked up because I Canny run NMap:", nmap_error.decode())
        sys.exit(1)

    print(nmap_output.decode())
    print("I've saved your loot here:", nmap_output_file)

if __name__ == "__main__":
    main()
