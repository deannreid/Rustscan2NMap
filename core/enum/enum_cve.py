import json
import os
import re
import subprocess
import time
import urllib.request
import urllib.parse

from colorama import Fore, Style

from core.utils import fncPrintMessage
from core.handlers import fncEnsureInstalled

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DELAY_NO_KEY   = 6.5   # NVD allows 5 req/30s without key
_DELAY_WITH_KEY = 0.7   # 50 req/30s with key

_SERVICE_RE = re.compile(r'^(\d+)/tcp\s+open\s+\S+\s+(.+)$')

_SEVERITY_COLOR = {
    "CRITICAL": Fore.LIGHTRED_EX,
    "HIGH":     Fore.RED,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.GREEN,
    "NONE":     Fore.WHITE,
    "UNKNOWN":  Fore.WHITE,
}


def _clean_version(raw: str) -> str:
    """Strip parenthetical nmap annotations like ((Debian)) or (protocol 2.0)."""
    return re.sub(r'\s*\(.*?\)', '', raw).strip()


def fncParseServiceVersions(nmap_output: str) -> list[tuple[str, str]]:
    """Return [(port, version_string), ...] deduplicated from Nmap text output."""
    seen: set[str] = set()
    services: list[tuple[str, str]] = []
    for line in nmap_output.splitlines():
        m = _SERVICE_RE.match(line.strip())
        if m:
            port    = m.group(1)
            version = _clean_version(m.group(2))
            if version and version not in seen:
                seen.add(version)
                services.append((port, version))
    return services


def _score_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "NONE"


def _extract_cvss(cve_item: dict) -> tuple[float, str]:
    metrics = cve_item.get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data  = entries[0].get("cvssData", {})
            score = float(data.get("baseScore", 0.0))
            sev   = data.get("baseSeverity", "").upper() or _score_to_severity(score)
            return score, sev
    return 0.0, "UNKNOWN"


def _get_description(cve_item: dict) -> str:
    for desc in cve_item.get("cve", {}).get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def _nvd_query(keyword: str, api_key: str | None = None) -> list[dict]:
    params = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": 10})
    headers = {"User-Agent": "rs2nm/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        req = urllib.request.Request(f"{NVD_API_URL}?{params}", headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode("utf-8")).get("vulnerabilities", [])
    except Exception as e:
        fncPrintMessage(f"NVD API error for '{keyword}': {e}", "warning")
        return []


def fncRunCVELookup(nmap_output: str, save_location: str, target: str,
                    api_key: str | None = None) -> dict:
    """
    Query NVD for each detected service version. Flags CRITICAL/HIGH CVEs.
    Returns {"critical": N, "high": N, "total": N}.
    """
    services = fncParseServiceVersions(nmap_output)
    if not services:
        fncPrintMessage("No versioned services in Nmap output; skipping CVE lookup.", "info")
        return {"critical": 0, "high": 0, "total": 0}

    delay = _DELAY_WITH_KEY if api_key else _DELAY_NO_KEY
    fncPrintMessage(
        f"CVE lookup: {len(services)} service(s)"
        + (" [API key in use]" if api_key else " [no API key — ~6s between requests]"),
        "info"
    )

    all_findings: list[dict] = []

    for i, (port, version) in enumerate(services):
        if i > 0:
            time.sleep(delay)
        fncPrintMessage(f"  [{i+1}/{len(services)}] {version} (port {port})", "info")
        for v in _nvd_query(version, api_key):
            cve_id     = v.get("cve", {}).get("id", "UNKNOWN")
            score, sev = _extract_cvss(v)
            all_findings.append({
                "port":     port,
                "service":  version,
                "cve":      cve_id,
                "score":    score,
                "severity": sev,
                "desc":     _get_description(v),
            })

    if not all_findings:
        fncPrintMessage("NVD returned no CVEs for the detected service versions.", "info")
        return {"critical": 0, "high": 0, "total": 0}

    all_findings.sort(key=lambda x: x["score"], reverse=True)

    critical = [f for f in all_findings if f["severity"] == "CRITICAL"]
    high     = [f for f in all_findings if f["severity"] == "HIGH"]

    if critical or high:
        fncPrintMessage(f"{len(critical)} CRITICAL / {len(high)} HIGH CVE(s) detected:", "warning")
        for f in (critical + high):
            color = _SEVERITY_COLOR.get(f["severity"], "")
            print(
                f"  {color}[{f['severity']} {f['score']:.1f}]{Style.RESET_ALL}"
                f"  {f['cve']}  —  {f['service']} (port {f['port']})"
            )
            if f["desc"]:
                snippet = f["desc"][:120].rstrip()
                if len(f["desc"]) > 120:
                    snippet += "…"
                print(f"    {snippet}")
    else:
        fncPrintMessage("No CRITICAL or HIGH CVEs found in NVD results.", "success")

    output_file = os.path.join(save_location, f"{target}_cve_report.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2)
    fncPrintMessage(f"Full CVE report ({len(all_findings)} entries) → {output_file}", "success")

    return {"critical": len(critical), "high": len(high), "total": len(all_findings)}


def fncRunSearchsploit(nmap_output: str, save_location: str, target: str) -> int:
    """
    Run searchsploit against each detected service version.
    Returns total exploit count found across all services.
    """
    if not fncEnsureInstalled("searchsploit", "apt install exploitdb  OR  snap install exploitdb"):
        return 0

    services = fncParseServiceVersions(nmap_output)
    if not services:
        fncPrintMessage("No service versions found; skipping SearchSploit.", "info")
        return 0

    fncPrintMessage(f"SearchSploit: checking {len(services)} service(s)…", "info")

    all_results: list[dict] = []
    total_count = 0

    for port, version in services:
        # Two-word keyword keeps results relevant without being overly narrow
        keyword = " ".join(version.split()[:2])
        try:
            proc = subprocess.Popen(
                ["searchsploit", "--json", keyword],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            out, _ = proc.communicate(timeout=30)
            data     = json.loads(out.decode("utf-8", errors="replace"))
            exploits = data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", [])

            if exploits:
                fncPrintMessage(
                    f"  {len(exploits)} exploit(s) for {Fore.YELLOW}{keyword}{Style.RESET_ALL}"
                    f" (port {port})",
                    "warning"
                )
                for e in exploits[:5]:
                    etype = e.get("Type", "?")
                    title = e.get("Title", "?")
                    print(f"    [{etype}] {title}")
                if len(exploits) > 5:
                    print(f"    … and {len(exploits) - 5} more (see report file)")
                total_count += len(exploits)
                all_results.append({
                    "port":     port,
                    "service":  version,
                    "keyword":  keyword,
                    "exploits": exploits,
                })
            else:
                fncPrintMessage(f"  No exploits for {keyword}", "info")

        except subprocess.TimeoutExpired:
            proc.kill()
            fncPrintMessage(f"  searchsploit timed out for {keyword}", "warning")
        except json.JSONDecodeError:
            fncPrintMessage(
                f"  searchsploit returned non-JSON for {keyword} "
                f"(try: searchsploit -u to update the database)",
                "warning"
            )
        except Exception as e:
            fncPrintMessage(f"  searchsploit error: {e}", "error")

    if all_results:
        output_file = os.path.join(save_location, f"{target}_searchsploit.json")
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2)
        fncPrintMessage(f"SearchSploit results → {output_file}", "success")

    return total_count
