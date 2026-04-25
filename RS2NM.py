#!/usr/bin/env python3
import argparse
import datetime
import ipaddress
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.enum.enum_scanner import fncRunRustscan, fncRunNmap, fncDetectOSFromNmap
from core.utils    import fncPrintMessage, fncIsAdmin, fncCheckPythonVersion, ask, set_non_interactive
from core.handlers import (
    fncCheckConfigFileExists,
    fncAddToHosts,
    fncGetDomainsFromNmap,
    fncSmbPortsOpen,
    fncLoadScanState,
    fncSaveScanState,
)
from core.pretty_stuff import fncPrintAsciiBanner, fncPrintBlurb, fncPrintVersion
from core.enum.enum_web      import fncRunWebFuzz
from core.enum.enum_sql      import fncRunSQLEnum
from core.enum.enum_linux    import fncRunLinuxEnum
from core.enum.enum_smb      import fncRunSMBEnum
from core.enum.enum_ldap     import fncRunLDAPEnum
from core.enum.enum_cve      import fncRunCVELookup, fncRunSearchsploit

_TARGET_RE = re.compile(
    r'^(?:'
    r'(?:\d{1,3}\.){3}\d{1,3}'                                        # IPv4
    r'|[0-9a-fA-F:]{2,39}'                                            # IPv6 (simple)
    r'|(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)'       # hostname/FQDN
    r')$'
)


# ── target resolution ────────────────────────────────────────────────────────

def _ping_sweep(cidr: str) -> list[str]:
    """Discover live hosts in a CIDR range using nmap -sn."""
    import shutil
    fncPrintMessage(f"Ping sweep on {cidr}…", "info")
    if shutil.which("nmap"):
        try:
            proc = subprocess.Popen(
                ["nmap", "-sn", "-n", "--open", cidr],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            out, _ = proc.communicate(timeout=120)
            hosts = re.findall(r'Nmap scan report for (\S+)', out.decode("utf-8", errors="replace"))
            if hosts:
                fncPrintMessage(f"Found {len(hosts)} live host(s) in {cidr}.", "success")
                return hosts
        except Exception as e:
            fncPrintMessage(f"Ping sweep failed ({e}); expanding range directly.", "warning")

    # Fallback: return all host addresses without live-check
    hosts = [str(h) for h in ipaddress.ip_network(cidr, strict=False).hosts()]
    fncPrintMessage(f"Returning {len(hosts)} addresses from {cidr} (no live-check).", "info")
    return hosts


def _read_target_file(path: str) -> list[str]:
    if not os.path.isfile(path):
        fncPrintMessage(f"Target file not found: {path}", "error")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    fncPrintMessage(f"Loaded {len(targets)} target(s) from {path}.", "success")
    return targets


def _resolve_targets(args) -> list[str]:
    """Return the final list of targets to scan."""
    if args.target_file:
        return _read_target_file(args.target_file)

    raw = args.target
    if not raw:
        fncPrintMessage("No target specified. Use a positional target, CIDR range, or --target-file.", "error")
        sys.exit(1)

    # CIDR range
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            fncPrintMessage(f"Invalid CIDR range: {raw!r}", "error")
            sys.exit(1)
        if net.num_addresses == 1:
            return [str(net.network_address)]
        return _ping_sweep(raw)

    # Single target validation
    if not _TARGET_RE.match(raw):
        fncPrintMessage(f"Invalid target: {raw!r}", "error")
        sys.exit(1)
    return [raw]


# ── per-target scan ──────────────────────────────────────────────────────────

def _target_save_dir(base: str, target: str, multi: bool) -> str:
    if not multi:
        return base
    safe = re.sub(r'[^\w.\-]', '_', target)
    path = os.path.join(base, safe)
    os.makedirs(path, exist_ok=True)
    return path


def _load_previous_nmap(nmap_base: str) -> str:
    nmap_txt = nmap_base + ".nmap"
    if os.path.isfile(nmap_txt):
        try:
            with open(nmap_txt, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            pass
    return ""


def _scan_target(target: str, save_dir: str, args, run_flags: dict) -> dict:
    """
    Full scan pipeline for a single target.
    Returns a summary dict for the aggregate report.
    """
    summary: dict = {
        "target":        target,
        "status":        "failed",
        "open_ports":    "",
        "os":            "unknown",
        "domains":       [],
        "cve_critical":  0,
        "cve_high":      0,
        "exploits_found": 0,
        "modules_run":   [],
    }

    fncPrintMessage(f"{'─'*50}", "info")
    fncPrintMessage(f"Scanning target: {target}", "success")

    # 1) RustScan
    open_ports = fncRunRustscan(target)
    if not open_ports.strip():
        fncPrintMessage(f"[{target}] No open ports; skipping.", "warning")
        summary["status"] = "no_ports"
        return summary

    summary["open_ports"] = open_ports

    # 2) Nmap — decide whether to (re)run
    state_file, state = fncLoadScanState(target)
    prev_ports     = state.get("ports")
    prev_nmap_done = state.get("nmap_complete", False)

    if prev_ports is None:
        fncPrintMessage("No prior port data; running Nmap.", "info")
        rerun = True
    elif prev_ports == open_ports and prev_nmap_done:
        fncPrintMessage("Ports unchanged since last scan.", "info")
        rerun = (ask("Skip Nmap? (y/n): ", default="y") != "y")
    elif prev_ports != open_ports:
        fncPrintMessage("Port set has changed:", "warning")
        fncPrintMessage(f"  Old: {prev_ports}", "info")
        fncPrintMessage(f"  New: {open_ports}", "info")
        if ask("Replace old scan with new ports? (y/n): ", default="y") == "y":
            state.update({"ports": open_ports, "nmap_complete": False})
            fncSaveScanState(state_file, state)
            rerun = True
        else:
            fncPrintMessage("Keeping previous port list; skipping Nmap.", "info")
            rerun = False
    else:
        fncPrintMessage("Previous scan incomplete; running Nmap.", "info")
        rerun = True

    nmap_base = os.path.join(save_dir, f"{target}_nmap_results")

    if rerun:
        nout, nerr = fncRunNmap(target, open_ports, nmap_base)
        if nerr:
            fncPrintMessage(f"Nmap stderr: {nerr}", "error")
        print(nout)
        fncPrintMessage(f"Nmap saved → {nmap_base}.nmap/.xml/.gnmap", "success")
        state.update({"ports": open_ports, "nmap_complete": True})
        fncSaveScanState(state_file, state)
        nmap_output = nout
    else:
        # Try to load previous nmap output so CVE/exploit lookup can still run
        nmap_output = _load_previous_nmap(nmap_base)

    # 3) Post-Nmap processing
    os_type = fncDetectOSFromNmap(nmap_output)
    fncPrintMessage(f"Detected OS: {os_type.upper()}", "info")
    summary["os"] = os_type

    domains = fncGetDomainsFromNmap(nmap_output)
    if domains:
        fncAddToHosts(target, domains)
        summary["domains"] = domains

    # 4) CVE lookup
    if run_flags["cve"] and nmap_output:
        cve_counts = fncRunCVELookup(
            nmap_output, save_dir, target,
            api_key=getattr(args, "nvd_api_key", None)
        )
        summary["cve_critical"]  = cve_counts["critical"]
        summary["cve_high"]      = cve_counts["high"]
        summary["modules_run"].append("cve")

    # 5) SearchSploit
    if run_flags["exploits"] and nmap_output:
        summary["exploits_found"] = fncRunSearchsploit(nmap_output, save_dir, target)
        summary["modules_run"].append("exploits")

    # 6) Conditional enumeration modules
    if run_flags["web"]:
        fncRunWebFuzz(target, save_dir)
        summary["modules_run"].append("web")

    if run_flags["sql"]:
        fncPrintMessage("Launching SQL enumeration…", "info")
        fncRunSQLEnum(nmap_base + ".nmap", target)
        summary["modules_run"].append("sql")

    if run_flags["smb"]:
        if fncSmbPortsOpen(open_ports):
            fncPrintMessage("Launching SMB enumeration…", "info")
            fncRunSMBEnum(target, save_dir)
            summary["modules_run"].append("smb")
        else:
            fncPrintMessage("SMB flag set but no SMB ports detected.", "warning")

    if run_flags["ldap"]:
        fncPrintMessage("Launching LDAP enumeration…", "info")
        fncRunLDAPEnum(target, save_dir, username=args.user, password=args.passwd)
        summary["modules_run"].append("ldap")

    if run_flags["linux"]:
        fncPrintMessage("Launching Linux enumeration…", "info")
        fncRunLinuxEnum(target, save_dir, username=args.user, password=args.passwd)
        summary["modules_run"].append("linux")

    summary["status"] = "complete"
    return summary


# ── aggregate report ─────────────────────────────────────────────────────────

def _write_aggregate_report(summaries: list[dict], save_location: str):
    stamp    = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(save_location, f"aggregate_scan_{stamp}.json")
    report   = {
        "scan_date":     datetime.datetime.now().isoformat(),
        "total_targets": len(summaries),
        "completed":     sum(1 for s in summaries if s["status"] == "complete"),
        "no_ports":      sum(1 for s in summaries if s["status"] == "no_ports"),
        "failed":        sum(1 for s in summaries if s["status"] == "failed"),
        "targets":       summaries,
    }
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    fncPrintMessage(f"Aggregate report → {out_file}", "success")

    # Print a quick summary table
    fncPrintMessage("─" * 60, "info")
    fncPrintMessage(
        f"{'TARGET':<20} {'STATUS':<10} {'PORTS':<8} {'OS':<9} {'CRIT':<6} {'HIGH':<6} {'EXPLOITS'}",
        "info"
    )
    fncPrintMessage("─" * 60, "info")
    for s in summaries:
        port_count = len(s["open_ports"].split(",")) if s["open_ports"] else 0
        fncPrintMessage(
            f"{s['target']:<20} {s['status']:<10} {port_count:<8} {s['os']:<9}"
            f" {s['cve_critical']:<6} {s['cve_high']:<6} {s['exploits_found']}",
            "success" if s["status"] == "complete" else "warning"
        )


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    try:
        if not fncIsAdmin():
            fncPrintMessage("Administrator privileges required.", "error")
            sys.exit(1)

        parser = argparse.ArgumentParser(
            description="RustScan 2 NMap — automated pentest enumeration",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        # Targets
        target_grp = parser.add_mutually_exclusive_group()
        target_grp.add_argument("target", nargs="?", default=None,
                                 help="Single IP, hostname, or CIDR range (e.g. 10.0.0.0/24)")
        target_grp.add_argument("--target-file", metavar="FILE",
                                 help="File containing one target per line")

        parser.add_argument("save_location", nargs="?", default=os.getcwd(),
                            help="Base directory to save output (default: cwd)")

        # Scan modules
        parser.add_argument("--web",   action="store_true", help="Web enumeration (ffuf, robots, headers…)")
        parser.add_argument("--sql",   action="store_true", help="SQL service enumeration")
        parser.add_argument("--smb",   action="store_true", help="SMB enumeration")
        parser.add_argument("--linux", action="store_true", help="Linux service enumeration")
        parser.add_argument("--ldap",  action="store_true", help="LDAP / AD enumeration")
        parser.add_argument("--cve",   action="store_true", help="CVE lookup via NVD API")
        parser.add_argument("--exploits", action="store_true",
                            help="SearchSploit exploit lookup (requires exploitdb)")
        parser.add_argument("--all-scans-captain", action="store_true",
                            help="Enable all scan modules")

        # Auth
        parser.add_argument("--user",   type=str, default=None, metavar="USERNAME")
        parser.add_argument("--passwd", type=str, default=None, metavar="PASSWORD")

        # CVE API key
        parser.add_argument("--nvd-api-key", type=str, default=None, metavar="KEY",
                            help="NVD API key (raises rate limit from 5 to 50 req/30s)")

        # Multi-target / behaviour
        parser.add_argument("--threads", type=int, default=1, metavar="N",
                            help="Parallel scan threads for multi-target mode (default: 1)")
        parser.add_argument("--yes", action="store_true",
                            help="Auto-accept all prompts (required for --threads > 1)")

        parser.add_argument("-v", "--version", action="store_true", help="Show version and exit")
        args = parser.parse_args()

        if args.version:
            fncPrintVersion()
            sys.exit(0)

        fncPrintAsciiBanner()
        fncPrintBlurb()
        fncCheckPythonVersion()
        fncCheckConfigFileExists()

        # Resolve target list
        targets = _resolve_targets(args)
        multi   = len(targets) > 1

        # Non-interactive mode: required for parallel, optional for sequential multi
        if args.yes or args.threads > 1 or multi:
            set_non_interactive(True)
            if args.threads > 1 and not args.yes:
                fncPrintMessage(
                    "Parallel mode active — all interactive prompts will use defaults.",
                    "warning"
                )

        if args.threads > 1 and not multi:
            fncPrintMessage("--threads has no effect with a single target.", "info")

        # Build run-flags once; shared across all target scans
        run_flags: dict[str, bool]
        if args.all_scans_captain:
            run_flags = {k: True for k in ("web", "sql", "smb", "linux", "ldap", "cve", "exploits")}
        else:
            run_flags = {
                "web":      args.web,
                "sql":      args.sql,
                "smb":      args.smb,
                "linux":    args.linux,
                "ldap":     args.ldap,
                "cve":      args.cve,
                "exploits": args.exploits,
            }

        save_base = args.save_location
        os.makedirs(save_base, exist_ok=True)

        summaries: list[dict] = []

        if args.threads > 1 and multi:
            fncPrintMessage(
                f"Launching {len(targets)} target(s) across {args.threads} thread(s)…",
                "info"
            )
            with ThreadPoolExecutor(max_workers=args.threads) as pool:
                futures = {
                    pool.submit(
                        _scan_target,
                        t,
                        _target_save_dir(save_base, t, multi),
                        args,
                        run_flags
                    ): t
                    for t in targets
                }
                for future in as_completed(futures):
                    t = futures[future]
                    try:
                        summaries.append(future.result())
                    except Exception as exc:
                        fncPrintMessage(f"[{t}] scan raised exception: {exc}", "error")
                        summaries.append({"target": t, "status": "failed",
                                          "open_ports": "", "os": "unknown",
                                          "domains": [], "cve_critical": 0,
                                          "cve_high": 0, "exploits_found": 0,
                                          "modules_run": []})
        else:
            for t in targets:
                save_dir = _target_save_dir(save_base, t, multi)
                try:
                    summaries.append(_scan_target(t, save_dir, args, run_flags))
                except Exception as exc:
                    fncPrintMessage(f"[{t}] scan raised exception: {exc}", "error")
                    summaries.append({"target": t, "status": "failed",
                                      "open_ports": "", "os": "unknown",
                                      "domains": [], "cve_critical": 0,
                                      "cve_high": 0, "exploits_found": 0,
                                      "modules_run": []})

        if multi:
            _write_aggregate_report(summaries, save_base)

    except KeyboardInterrupt:
        fncPrintMessage("Interrupted by user. Exiting…", "error")
        sys.exit(1)


if __name__ == "__main__":
    main()
