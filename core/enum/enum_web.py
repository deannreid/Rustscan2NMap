import os
import tempfile
import subprocess
import urllib.request
import platform
import socket 
from config import DOM_LIST
from core.utils import fncPrintMessage
from core.handlers import fncAddToHosts, fncEnsureInstalled

# Detect Windows for new console spawning
IS_WINDOWS = platform.system().lower() == "windows"
CREATE_NEW_CONSOLE = 0x00000010 if IS_WINDOWS else 0

def fncGetWebPort(target):
    """
    Check ports 80 and 443; return one to use (as string).
    If both open, prompt; if neither, ask manually.
    """
    fncPrintMessage("Checking HTTP(S) ports on target…", "info")
    open_ports = []
    for p in (80, 443):
        try:
            with socket.create_connection((target, p), timeout=1):
                open_ports.append(p)
        except Exception:
            pass

    if len(open_ports) == 1:
        return str(open_ports[0])
    if len(open_ports) == 2:
        choice = input("Both 80 and 443 are open. Which to use? [80/443]: ").strip()
        return choice if choice in ("80", "443") else "80"
    return input("Neither 80 nor 443 open—enter port to use: ").strip()

def fncEnsureHostEntry(target):
    """
    Ask if the domain is in hosts; if not, prompt for IP and add it.
    """
    ans = input(f"Is '{target}' mapped in your hosts file? (y/n): ").strip().lower()
    if ans != 'y':
        ip = input(f"Enter the IP address for '{target}': ").strip()
        fncAddToHosts(ip, target)

def fncFuzzDirectories(target, save_location, base_url):
    """
    Directory fuzzing with ffuf against base_url/FUZZ.
    """
    if not fncEnsureInstalled("ffuf", "e.g., apt install ffuf"):
        return
    
    print("\n===================================")
    fncPrintMessage(f"Directory fuzz → {base_url}/FUZZ", "info")
    if input("Custom wordlist? (y/n): ").strip().lower() == 'y':
        wordlist = input("Path to wordlist: ").strip()
    else:
        wordlist = DOM_LIST
    if not os.path.isfile(wordlist):
        fncPrintMessage(f"Wordlist not found: {wordlist}", "error")
        return

    # save wrapper under ~/.rs2nm/wrappers/{target}/
    wrapper_dir = os.path.expanduser(f"~/.rs2nm/wrappers/{target}")
    os.makedirs(wrapper_dir, exist_ok=True)
    wrapper = os.path.join(wrapper_dir, "ffuf_dirs_wrapper.py")

    with open(wrapper, "w", encoding="utf-8") as w:
        w.write(f'''import sys, subprocess, os, signal
print("FFUF directory fuzz is running in silent mode...")
args = sys.argv
if len(args) < 5: sys.exit(1)
target, save_location, base_url, wordlist = args[1:5]
output = os.path.join(save_location, f"{{target}}_dirs.json")
cmd = ["ffuf", "-s",
    "-u", f"{{base_url}}/FUZZ",
    "-w", f"{{wordlist}}:FUZZ",
    "-of", "json", "-t", "500", "-fc", "403", "-ac", "-v"
]
lines = []
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
signal.signal(signal.SIGINT, lambda s,f: proc.terminate())
for line in proc.stdout:
    print(line, end=""); lines.append(line)
proc.wait()
with open(output, "w", encoding="utf-8") as f:
    f.writelines(lines)
''')

    args = ["python", wrapper, target, save_location, base_url, wordlist]
    if IS_WINDOWS:
        subprocess.Popen(args, creationflags=CREATE_NEW_CONSOLE)
    else:
        subprocess.Popen(["python3", wrapper, target, save_location, base_url, wordlist], cwd=save_location)

def fncFuzzSubdomains(target, save_location, base_url):
    """
    Subdomain fuzzing with ffuf (Host: FUZZ.<target>).
    """
    if not fncEnsureInstalled("ffuf", "e.g., apt install ffuf"):
        return
    
    print("\n===================================")
    fncPrintMessage(f"Subdomain fuzz → {base_url}", "info")
    sizes = ["huge","large","medium","small","tiny"]
    print("Select Nokovo list size:")
    for i, sz in enumerate(sizes, 1):
        print(f"  {i}. n0kovo_subdomains_{sz}.txt")
    print(f"  {len(sizes)+1}. Custom path")
    choice = input(f"[1-{len(sizes)+1}]: ").strip()
    idx = int(choice) if choice.isdigit() else 1
    if 1 <= idx <= len(sizes):
        sz = sizes[idx-1]
        wordlist = os.path.expanduser(f"~/.rs2nm/nokovo_subdomains_{sz}.txt")
        if not os.path.isfile(wordlist):
            os.makedirs(os.path.dirname(wordlist), exist_ok=True)
            urllib.request.urlretrieve(
                "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/refs/heads/main/"
                f"n0kovo_subdomains_{sz}.txt", wordlist)
    else:
        wordlist = input("Custom wordlist path: ").strip()
    if not os.path.isfile(wordlist):
        fncPrintMessage(f"Wordlist not found: {wordlist}", "error")
        return

    # save wrapper under ~/.rs2nm/wrappers/{target}/
    wrapper_dir = os.path.expanduser(f"~/.rs2nm/wrappers/{target}")
    os.makedirs(wrapper_dir, exist_ok=True)
    wrapper = os.path.join(wrapper_dir, "ffuf_subs_wrapper.py")

    with open(wrapper, "w", encoding="utf-8") as w:
        w.write(f'''import sys, subprocess, os, signal
print("FFUF subdomain fuzz is running in silent mode...")
args = sys.argv
if len(args) < 5: sys.exit(1)
target, save_location, base_url, wordlist = args[1:5]
output = os.path.join(save_location, f"{{target}}_subs.json")
cmd = ["ffuf", "-s",
    "-w", f"{{wordlist}}:FUZZ",
    "-u", f"{{base_url}}/",
    "-H", f"Host: FUZZ.{{target}}",
    "-of", "json", "-t", "500", "-fc", "403", "-ac", "-v"
]
lines = []
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
signal.signal(signal.SIGINT, lambda s,f: proc.terminate())
for line in proc.stdout:
    print(line, end=""); lines.append(line)
proc.wait()
with open(output, "w", encoding="utf-8") as f:
    f.writelines(lines)
''')

    args = ["python", wrapper, target, save_location, base_url, wordlist]
    if IS_WINDOWS:
        subprocess.Popen(args, creationflags=CREATE_NEW_CONSOLE)
    else:
        subprocess.Popen(["python3", wrapper, target, save_location, base_url, wordlist], cwd=save_location)

def fncScanRobotsTxt(target, save_location, base_url):
    """
    Fetch and save robots.txt. 
    If not found (HTTP error), warn and exit.
    """
    if not fncEnsureInstalled("curl", "e.g., apt install curl"):
        return
    
    print("\n===================================")
    fncPrintMessage("Fetching robots.txt…", "info")
    url = f"{base_url}/robots.txt"
    output = os.path.join(save_location, f"{target}_robots.txt")

    # Use -f to fail on HTTP ≥400
    curl_cmd = ["curl", "-sSf"]
    if url.startswith("https://"):
        curl_cmd.append("-k")
    curl_cmd.append(url)

    try:
        resp = subprocess.check_output(curl_cmd)
        if not resp.strip():
            fncPrintMessage(f"robots.txt not found on {target}", "warning")
            return
        with open(output, "wb") as f:
            f.write(resp)
        fncPrintMessage(f"robots.txt saved → {output}", "success")
    except subprocess.CalledProcessError:
        fncPrintMessage(f"robots.txt not found on {target}", "warning")
    except Exception as e:
        fncPrintMessage(f"robots.txt fetch error: {e}", "error")

def fncScanSitemapXml(target, save_location, base_url):
    """
    Fetch and save sitemap.xml.
    If not found (HTTP ≥400) or timed out, warn and exit.
    """
    if not fncEnsureInstalled("curl", "e.g., apt install curl"):
        return
    
    print("\n===================================")
    fncPrintMessage("Fetching sitemap.xml…", "info")
    url = f"{base_url}/sitemap.xml"
    output = os.path.join(save_location, f"{target}_sitemap.xml")

    curl_cmd = ["curl", "-sSf", "-m", "10"]
    if url.startswith("https://"):
        curl_cmd.append("-k")
    curl_cmd.append(url)

    try:
        resp = subprocess.check_output(curl_cmd, timeout=12)
        if not resp.strip():
            fncPrintMessage(f"sitemap.xml not found on {target}", "warning")
            return
        with open(output, "wb") as f:
            f.write(resp)
        fncPrintMessage(f"sitemap.xml saved → {output}", "success")

    except subprocess.CalledProcessError:
        fncPrintMessage(f"sitemap.xml not found on {target}", "warning")
    except subprocess.TimeoutExpired:
        fncPrintMessage("sitemap.xml request timed out after 10s", "warning")
    except Exception as e:
        fncPrintMessage(f"sitemap.xml fetch error: {e}", "error")

def fncScanHeaders(target, save_location, base_url):
    """
    Grab response headers using curl -I, fail on HTTP errors.
    """
    if not fncEnsureInstalled("curl", "e.g., apt install curl"):
        return
    
    print("\n===================================")
    fncPrintMessage("Gathering HTTP headers…", "info")
    output = os.path.join(save_location, f"{target}_headers.txt")

    curl_cmd = ["curl", "-sSfI"]
    if base_url.startswith("https://"):
        curl_cmd.insert(1, "-k")  # ["curl","-k","-sSfI",...]
    curl_cmd.append(base_url)

    try:
        headers = subprocess.check_output(curl_cmd)
        if not headers.strip():
            fncPrintMessage(f"Headers not found on {target}", "warning")
            return
        with open(output, "wb") as f:
            f.write(headers)
        fncPrintMessage(f"Headers saved → {output}", "success")
    except subprocess.CalledProcessError:
        fncPrintMessage(f"Headers not found on {target}", "warning")
    except Exception as e:
        fncPrintMessage(f"Header scan error: {e}", "error")

def fncScanWafW00f(target, save_location, base_url):
    """
    Fingerprint WAF with wafw00f.
    """
    if not fncEnsureInstalled("wafw00f", "pip install wafw00f"):
        return
    
    print("\n===================================")
    fncPrintMessage("Running WAF detection…", "info")
    output = os.path.join(save_location, f"{target}_wafw00f.txt")
    try:
        out = subprocess.check_output(["wafw00f", base_url])
        with open(output, "wb") as f:
            f.write(out)
        fncPrintMessage(f"WAF scan saved → {output}", "success")
    except Exception as e:
        fncPrintMessage(f"WAF detection failed: {e}", "error")

def fncScanParams(target, save_location, base_url):
    """
    Run ParamSpider for parameter discovery.
    """
    if not fncEnsureInstalled("paramspider", "pip install paramspider"):
        return

    print("\n===================================")
    fncPrintMessage("Running ParamSpider…", "info")
    output = os.path.join(save_location, f"{target}_params.txt")
    try:
        out = subprocess.check_output([
            "python3", "-m", "paramspider", "-d", target, "-o", output
        ])
        fncPrintMessage(f"Params saved → {output}", "success")
    except Exception as e:
        fncPrintMessage(f"ParamSpider failed: {e}", "error")

def fncScanCMSmap(target, save_location):
    """
    CMS detection & known-vuln checks via CMSmap.
    """
    if not fncEnsureInstalled("cmsmap", "pip install cmsmap"):
        return
    
    print("\n===================================")
    fncPrintMessage("Running CMSmap…", "info")
    output = os.path.join(save_location, f"{target}_cmsmap.txt")
    cmd = ["cmsmap", target, "--deep","-o", output]
    try:
        subprocess.run(cmd, cwd=save_location, check=True)
        fncPrintMessage(f"CMSmap results → {output}", "success")
    except Exception as e:
        fncPrintMessage(f"CMSmap failed: {e}", "error")

def fncScanCORS(target, save_location, base_url):
    """
    Check for permissive CORS configurations.
    """
    if not fncEnsureInstalled("curl", "e.g., apt install curl"):
        return

    fncPrintMessage("Testing CORS…", "info")
    output = os.path.join(save_location, f"{target}_cors.txt")

    curl_cmd = ["curl", "-k", "-I", "-f", "-m", "5", base_url]

    try:
        proc = subprocess.run(
            curl_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=save_location
        )
        # Non-zero return code indicates HTTP error (including SSL issues)
        if proc.returncode != 0:
            fncPrintMessage(f"CORS headers not found on {target} (curl exit {proc.returncode})", "warning")
            return

        headers = proc.stdout.decode().splitlines()
        cors_headers = [h for h in headers if h.lower().startswith("access-control-allow-origin")]
        if not cors_headers:
            fncPrintMessage("No CORS header present", "warning")
        else:
            with open(output, "w") as f:
                f.write("\n".join(cors_headers))
            fncPrintMessage(f"CORS headers saved → {output}", "success")

    except subprocess.TimeoutExpired:
        fncPrintMessage("CORS check timed out after 5s", "warning")
    except Exception as e:
        fncPrintMessage(f"CORS scan error: {e}", "error")

def fncScanSwagger(target, save_location, base_url):
    """
    Fetch Swagger/OpenAPI spec if exposed.
    """
    for path in ("/swagger.json","/openapi.json"):
        fncPrintMessage(f"Trying {path}…", "info")
        try:
            resp = subprocess.check_output(
                ["curl","-s","-k", base_url+path], timeout=5
            )
            if resp.strip().startswith(b"{"):
                out = os.path.join(save_location, f"{target}{path.replace('/','.')}")  
                with open(out,"wb") as f: f.write(resp)
                fncPrintMessage(f"Spec saved → {out}", "success")
                return
        except Exception:
            pass
    fncPrintMessage("No Swagger/OpenAPI spec found", "warning")

def fncRunWebFuzz(target, save_location):
    """
    Full web enumeration:
      • Ensure hosts entry
      • Pick HTTP/S port
      • Run all web scans
    """
    print("\n===================================")
    fncPrintMessage("Starting full web enumeration…", "info")
    print("===================================\n")

    fncEnsureHostEntry(target)

    port = fncGetWebPort(target)
    if port == "443":
        base_url = f"https://{target}"
    else:
        base_url = f"http://{target}:{port}"

    fncPrintMessage(f"Using base URL: {base_url}", "info")

    fncFuzzDirectories(target, save_location, base_url)
    fncFuzzSubdomains(target, save_location, base_url)
    fncScanRobotsTxt(target, save_location, base_url)
    fncScanSitemapXml(target, save_location, base_url)
    fncScanHeaders(target, save_location, base_url)
    fncScanWafW00f(target, save_location, base_url)
    fncScanParams(target, save_location, base_url)
    fncScanCORS(target, save_location, base_url)
    fncScanCMSmap(target, save_location)
    fncScanSwagger(target, save_location, base_url)