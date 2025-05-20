#!/usr/bin/env python3
import argparse
import os
import sys
import json
import random
from colorama import Fore, Style

# ← Point at the renamed scanner module
from core.enum.enum_scanner import fncRunRustscan, fncRunNmap, fncDetectOSFromNmap

from core.utils    import fncPrintMessage, fncIsAdmin, fncCheckPythonVersion
from core.handlers import (
    fncCheckConfigFileExists,
    fncAddToHosts,
    fncGetDomainsFromNmap,
    fncSmbPortsOpen
)
from core.pretty_stuff import (
    fncPrintAsciiBanner,
    fncPrintBlurb,
    fncPrintVersion
)
from core.enum.enum_web import fncRunWebFuzz
from core.enum.enum_sql import fncRunSQLEnum

def main():
    try:
        # --- privilege, version, banner, python version, config checks ---
        if not fncIsAdmin():
            fncPrintMessage("Administrator privileges required.", "error")
            sys.exit(1)

        fncCheckPythonVersion()
        fncCheckConfigFileExists()

        parser = argparse.ArgumentParser(description="RustScan 2 NMap")
        parser.add_argument("target", help="Target IP or hostname")
        parser.add_argument("save_location", nargs="?", default=os.getcwd(),
                            help="Where to save output")
        parser.add_argument("--web",  action="store_true", help="Web enumeration")
        parser.add_argument("--sql",  action="store_true", help="SQL enumeration")
        parser.add_argument("--smb",  action="store_true", help="SMB enumeration")
        parser.add_argument("--e4l",  action="store_true", help="enum4linux-ng")
        parser.add_argument("--ldap", action="store_true", help="LDAP enumeration")
        parser.add_argument("--all-scans-captain", action="store_true",
                            help="Run everything")
        parser.add_argument("-v","--version", action="store_true", help="Show version")
        args = parser.parse_args()

        if args.version:
            # print version…
            sys.exit(0)

        # show banner/blurb…
        fncPrintAsciiBanner()
        fncPrintBlurb()

        # Determine which to run
        if args.all_scans_captain:
            run_web = run_sql = run_smb = run_e4l = run_ldap = True
        else:
            run_web = args.web
            run_sql = args.sql
            run_smb = args.smb
            run_e4l = args.e4l
            run_ldap = args.ldap

        target        = args.target
        save_location = args.save_location

        # --- 1) RustScan ---
        open_ports = fncRunRustscan(target)
        if not open_ports.strip():
            fncPrintMessage("No open ports; aborting.", "warning")
            return

        # --- 2) Nmap (with simple resume logic) ---
        state_dir  = os.path.expanduser("~/.rs2nm/temp")
        os.makedirs(state_dir, exist_ok=True)
        state_file = os.path.join(state_dir, f"rs2nm_{target}.json")

        rerun_nmap = True
        if os.path.exists(state_file):
            with open(state_file) as sf:
                st = json.load(sf)
            if st.get("nmap_complete"):
                ans = input("Nmap already done. Re-run? (y/n): ").strip().lower()
                rerun_nmap = (ans == 'y')

        nmap_base = os.path.join(save_location, f"{target}_nmap_results")
        if rerun_nmap:
            nmap_out, nmap_err = fncRunNmap(target, open_ports, nmap_base)
            if nmap_err:
                fncPrintMessage(f"Nmap error: {nmap_err}", "error")
            print(nmap_out)
            fncPrintMessage(f"Nmap saved → {nmap_base}.nmap/.xml/.gnmap", "success")
            # mark complete
            with open(state_file, "w") as sf:
                json.dump({"nmap_complete": True}, sf)
            nmap_output = nmap_out
        else:
            nmap_output = ""

        # --- 3) Post‐Nmap processing ---
        os_type = fncDetectOSFromNmap(nmap_output)
        fncPrintMessage(f"Detected OS: {os_type.upper()}", "info")

        domains = fncGetDomainsFromNmap(nmap_output)
        if domains:
            fncAddToHosts(target, domains)

        # --- 4) Conditional enumeration ---
        if run_web:
            fncRunWebFuzz(target, save_location)

        if run_sql:
            fncPrintMessage("Launching SQL enumeration…", "info")
            nmap_txt = nmap_base + ".nmap"
            fncRunSQLEnum(nmap_txt, target)

        if run_smb and fncSmbPortsOpen(open_ports):
            fncRunNetExecSMB(target, save_location)

        if run_e4l:
            fncRunEnum4LinuxNG(target, save_location)

        if run_ldap:
            fncRunLdapSearch(target, save_location)

    except KeyboardInterrupt:
        fncPrintMessage("Interrupted by user. Exiting…", "error")
        sys.exit(1)


if __name__ == "__main__":
    main()
