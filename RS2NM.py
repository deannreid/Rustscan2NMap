#!/usr/bin/env python3
import argparse
import os
import sys
from os.path import expanduser, join
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
    fncSmbPortsOpen,
    fncLoadScanState,
    fncSaveScanState
)
from core.pretty_stuff import (
    fncPrintAsciiBanner,
    fncPrintBlurb,
    fncPrintVersion
)

from core.enum.enum_web import fncRunWebFuzz
from core.enum.enum_sql import fncRunSQLEnum
from core.enum.enum_linux import fncRunLinuxEnum

def main():
    try:
        # --- privilege, version, banner, python version, config checks ---
        if not fncIsAdmin():
            fncPrintMessage("Administrator privileges required.", "error")
            sys.exit(1)

        parser = argparse.ArgumentParser(description="RustScan 2 NMap")
        parser.add_argument("target", help="Target IP or hostname")
        parser.add_argument("save_location", nargs="?", default=os.getcwd(),
                            help="Where to save output")
        parser.add_argument("--web",  action="store_true", help="Web enumeration")
        parser.add_argument("--sql",  action="store_true", help="SQL enumeration")
        parser.add_argument("--smb",  action="store_true", help="SMB enumeration")
        parser.add_argument("--linux",  action="store_true", help="Linux Enum")
        parser.add_argument("--ldap", action="store_true", help="LDAP enumeration")
        parser.add_argument("--all-scans-captain", action="store_true",
                            help="Run everything")
        
        parser.add_argument("--user", action="store_true", help="Username")
        parser.add_argument("--passwd", action="store_true", help="Password")
        parser.add_argument("-v","--version", action="store_true", help="Show version")
        args = parser.parse_args()

        if args.version:
            # print version…
            sys.exit(0)

        # show banner/blurb…
        fncPrintAsciiBanner()
        fncPrintBlurb()
        fncCheckPythonVersion()
        fncCheckConfigFileExists()

        # Determine which to run
        if args.all_scans_captain:
            run_web = run_sql = run_smb = run_e4l = run_ldap = True
        else:
            run_web = args.web
            run_sql = args.sql
            run_linux = args.linux

        target        = args.target
        save_location = args.save_location

        # --- 1) RustScan ---
        open_ports = fncRunRustscan(target)
        if not open_ports.strip():
            fncPrintMessage("No open ports; aborting.", "warning")
            return

        state_file, state = fncLoadScanState(target)
        prev_ports     = state.get("ports")
        prev_nmap_done = state.get("nmap_complete", False)

        if prev_ports is None:
            fncPrintMessage("No prior port data; running Nmap.", "info")
            rerun = True
        elif prev_ports == open_ports and prev_nmap_done:
            fncPrintMessage("No changes in open ports since last scan.", "info")
            rerun = (input("Skip Nmap? (y/n): ").strip().lower() != 'y')
        elif prev_ports != open_ports:
            fncPrintMessage("Port set has changed:", "warning")
            fncPrintMessage(f"Old: {prev_ports}", "info")
            fncPrintMessage(f"New: {open_ports}", "info")
            if input("Replace old scan with new ports? (y/n): ").strip().lower() == 'y':
                state.update({"ports": open_ports, "nmap_complete": False})
                fncSaveScanState(state_file, state)
                rerun = True
            else:
                fncPrintMessage("Keeping previous port list; skipping Nmap.", "info")
                rerun = False
        else:
            fncPrintMessage("Previous scan incomplete; running Nmap.", "info")
            rerun = True

        nmap_base = os.path.join(save_location, f"{target}_nmap_results")
        if rerun:
            nout, nerr = fncRunNmap(target, open_ports, nmap_base)
            if nerr:
                fncPrintMessage(f"Nmap error: {nerr}", "error")
            print(nout)
            fncPrintMessage(f"Nmap saved → {nmap_base}.nmap/.xml/.gnmap", "success")
            state.update({"ports": open_ports, "nmap_complete": True})
            fncSaveScanState(state_file, state)
            nmap_output = nout
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

        if run_linux:
            fncRunLinuxEnum(
                target,
                save_location,
                username=args.user,
                password=args.passwd
            )

    except KeyboardInterrupt:
        fncPrintMessage("Interrupted by user. Exiting…", "error")
        sys.exit(1)


if __name__ == "__main__":
    main()
