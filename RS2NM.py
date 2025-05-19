import argparse
import os
import platform
import random
import sys
from colorama import Fore, Style

from core.scanner import fncRunRustscan, fncRunNmap, fncDetectOSFromNmap
#from core.enum import fncRunEnum4LinuxNG, fncRunLdapSearch, fncRunNetExecSMB, fncRunBloodhound
from core.utils import fncPrintMessage, fncIsAdmin, fncCheckPythonVersion
from core.handlers import fncCheckConfigFileExists, fncAddToHosts, fncGetDomainsFromNmap, fncSmbPortsOpen
from core.enum.enum_web import fncRunWebFuzz


def fncPrintAsciiBanner():
    print(Fore.CYAN + """
        _|_|_|      _|_|_|        _|_|        _|      _|  _|      _|
        _|    _|  _|            _|    _|      _|_|    _|  _|_|  _|_|
        _|_|_|      _|_|            _|        _|  _|  _|  _|  _|  _|
        _|    _|        _|        _|          _|    _|_|  _|      _|
        _|    _|  _|_|_|        _|_|_|_|      _|      _|  _|      _|

        The soon to be all-in-one pentest enumeration tool.

        ------------------------------------------------
        ::        %INSERT RELEVANT DISCORD HERE       ::
        :: https://github.com/deannreid/Rustscan2NMap ::
        ------------------------------------------------
    """ + Style.RESET_ALL)

def fncPrintBlurb():
    blurbs = [
        "Enumerating services: Like snooping on your neighbour's Wi-Fi, but legal.",
        "Exploring services: The geek's way of saying 'I'm just curious!'",
        "Mapping the network: It's like drawing a treasure map, but with routers and switches.",
        "Sniffing packets: Catching data in the air like a digital butterfly net.",
        "Probing the depths: Finding hidden gems in your network.",
        "Deploying proxies: Sending a digital bodyguard to deliver your data."
    ]
    print("            " + random.choice(blurbs) + "\n")

def fncPrintVersion():
    print(Fore.CYAN + """
    ==============================================
    | RustScan 2 NMap - Scottish Edition          |
    | Version: 1.9.5                              |
    | Developed by Dean with a bit of love        |
    ==============================================
    | Script to automagically funnel Rustscan     |
    | results into Nmap, and follow up with       |
    | enum4linux-ng, ldapsearch, and optionally   |
    | BloodHound scans                            |
    ==============================================
    """ + Style.RESET_ALL)


def main():
    try:
        parser = argparse.ArgumentParser(description='RustScan 2 NMap - Scottish Edition')
        parser.add_argument('target', help='Target IP address')
        parser.add_argument('save_location', nargs='?', default=os.getcwd(), help='Save location (default: current directory)')
        parser.add_argument('--smb', action='store_true', help='Run NetExec SMB enumeration')
        parser.add_argument('--e4l', action='store_true', help='Run enum4linux-ng enumeration')
        parser.add_argument('--ldap', action='store_true', help='Run LDAP enumeration')
        parser.add_argument('--bloodhound', action='store_true', help='Run BloodHound enumeration')
        parser.add_argument('--web', action='store_true', help='FFuF dat Domain')
        parser.add_argument('--all-scans-captain', action='store_true', help='Run all enumeration tools')
        parser.add_argument('-v', '--version', action='store_true', help='Show version and exit')
        args = parser.parse_args()

        fncPrintAsciiBanner()
        fncPrintBlurb()

        fncCheckPythonVersion()
        fncCheckConfigFileExists()

        if not fncIsAdmin():
            fncPrintMessage("This script requires administrative privileges.", "error")
            sys.exit(1)

        if args.version:
            fncPrintVersion()
            sys.exit(0)

        target = args.target
        save_location = args.save_location

        run_smb = run_e4l = run_ldap = run_bloodhound = False
        if args.all_scans_captain:
            run_smb = run_e4l = run_ldap = run_bloodhound = True
        else:
            run_smb = args.smb
            run_e4l = args.e4l
            run_ldap = args.ldap
            run_bloodhound = args.bloodhound
            run_web = args.web

        open_ports = fncRunRustscan(target)
        if open_ports.strip() == "":
            fncPrintMessage("No ports found. Skipping Nmap and enumeration.", "warning")
            return

        """ # Check if scan file has Nmap completed already
        from os.path import expanduser, join
        import json

        scan_path = join(expanduser("~/.rs2nm"), "temp", f"rs2nm_{target}.json")
        nmap_already_done = False
        if os.path.exists(scan_path):
            try:
                with open(scan_path, "r") as f:
                    scan_data = json.load(f)
                    if scan_data.get("nmap_complete"):
                        response = input("Nmap already completed for this target. Re-run Nmap? (y/n): ").strip().lower()
                        if response != 'y':
                            fncPrintMessage("Skipping Nmap based on saved state.", "info")
                            #return
            except Exception as e:
                fncPrintMessage(f"Could not read scan state: {e}", "warning")

        if nmap_already_done:
            nmap_output = ""
        else:
            nmap_output_file = os.path.join(save_location, f"{target}_nmap_results")
            nmap_output, nmap_error = fncRunNmap(target, open_ports, nmap_output_file)

            if nmap_error:
                fncPrintMessage("Nmap error:" + nmap_error, "error")

            print(nmap_output)
            fncPrintMessage(f"Nmap results saved to: {nmap_output_file}", "success")

            # Update scan file to record Nmap as complete
            try:
                with open(scan_path, "r") as f:
                    scan_data = json.load(f)
                scan_data["nmap_complete"] = True
                with open(scan_path, "w") as f:
                    json.dump(scan_data, f)
                fncPrintMessage("Updated scan file with Nmap completion flag.", "info")
            except Exception as e:
                fncPrintMessage(f"Could not update scan file with Nmap flag: {e}", "warning")
            fncPrintMessage(f"Nmap results saved to: {nmap_output_file}", "success")

            # Update scan file to record Nmap as complete
            try:
                with open(scan_path, "r") as f:
                    scan_data = json.load(f)
                scan_data["nmap_complete"] = True
                with open(scan_path, "w") as f:
                    json.dump(scan_data, f)
                fncPrintMessage("Updated scan file with Nmap completion flag.", "info")
            except Exception as e:
                fncPrintMessage(f"Could not update scan file with Nmap flag: {e}", "warning")

        
        os_type = fncDetectOSFromNmap(nmap_output)
        fncPrintMessage(f"Detected OS: {os_type.upper()}", "info")

        domains = fncGetDomainsFromNmap(nmap_output)
        for domain in domains:
            fncAddToHosts(target, domain)
 """
        if run_smb and fncSmbPortsOpen(open_ports):
            fncRunNetExecSMB(target, save_location)

        if run_e4l:
            fncRunEnum4LinuxNG(target, save_location)

        if run_ldap:
            fncRunLdapSearch(target, save_location)

        if run_web:
            fncRunWebFuzz(target, save_location)

        """ if run_bloodhound:
            if domains:
                user = input("Enter username for BloodHound: ")
                pw = input("Enter password for BloodHound: ")
                if user and pw:
                    fncRunBloodhound(target, save_location, domains[0], user, pw)
                else:
                    fncPrintMessage("Missing credentials. Skipping BloodHound.", "warning")
            else:
                fncPrintMessage("No domain found. Skipping BloodHound.", "warning")
 """
    except KeyboardInterrupt:
        fncPrintMessage("Interrupted. Exiting...", "error")
        sys.exit(1)


if __name__ == "__main__":
    main()
