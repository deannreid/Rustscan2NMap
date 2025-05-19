# Global configuration variables

import os

CONFIG_PATH = os.path.expanduser("~/.rs2nm/config.json")
DEFAULT_SAVE_LOCATION = os.getcwd()

# Default ports commonly associated with SMB
SMB_PORTS = {'445', '137', '138', '139'}

# LDAP and AD-related ports
LDAP_PORTS = {'389', '636', '3268', '3269'}

# Common web server ports
WEB_PORTS = {'80', '443', '8080', '8443'}

# FTP
FTP_PORTS = {'20', '21'}

# SSH
SSH_PORTS = {'22'}

# RDP
RDP_PORTS = {'3389'}

# WinRM (often used for remote PowerShell)
WINRM_PORTS = {'5985', '5986'}

# MSSQL
MSSQL_PORTS = {'1433', '1434'}

# MySQL
MYSQL_PORTS = {'3306'}

# PostgreSQL
POSTGRES_PORTS = {'5432'}

# RPC
RPC_PORTS = {'135'}

# DNS
DNS_PORTS = {'53'}

# All port categories for lookup
PORT_CATEGORIES = {
    'SMB': SMB_PORTS,
    'LDAP': LDAP_PORTS,
    'WEB': WEB_PORTS,
    'FTP': FTP_PORTS,
    'SSH': SSH_PORTS,
    'RDP': RDP_PORTS,
    'WINRM': WINRM_PORTS,
    'MSSQL': MSSQL_PORTS,
    'MYSQL': MYSQL_PORTS,
    'POSTGRES': POSTGRES_PORTS,
    'RPC': RPC_PORTS,
    'DNS': DNS_PORTS
}

# Hosts file location based on OS
HOSTS_FILE = r'C:\Windows\System32\drivers\etc\hosts' if os.name == 'nt' else '/etc/hosts'


## Wordlists
SUB_DOM_LIST = ""

DOM_LIST = "directory-list-1.0.txt"