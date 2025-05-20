from colorama import Fore, Style
import random

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