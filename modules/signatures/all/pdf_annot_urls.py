# Copyright (C) 2024 Wassime BATTA
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import socket, os, asyncio
from urllib.parse import urlparse, parse_qs
from lib.cuckoo.common.abstracts import Signature, CUCKOO_ROOT
import threading

def is_blacklisted(target, dnsbl_servers):
    try:
        ip_address = socket.gethostbyname(target)
        for server in dnsbl_servers:
            query = '.'.join(reversed(str(ip_address).split("."))) + "." + server
            try:
                threading.Thread(target=socket.gethostbyname, args=(query,)).start()
                return True, server  # Found blacklisted server
            except socket.error:
                pass
        return False, None  # No blacklisted server found
    except socket.gaierror:
        return "Invalid domain or IP address.", None


def extract_domains(url):
    parsed_url = urlparse(url)
    domains = set()
    if parsed_url.netloc:
        domains.add(parsed_url.netloc)
    query_params = parse_qs(parsed_url.query)
    for param_values in query_params.values():
        for value in param_values:
            param_url = urlparse(value)
            if param_url.netloc:
                domains.add(param_url.netloc)
    return domains
    

class PDF_Annot_URLs_Checker(Signature):
    name = "pdf_annot_urls_checker"
    description = "The PDF contains a Link Annotation"
    severity = 2  # Default severity
    categories = ["static"]
    authors = ["Wassime BATTA"]
    minimum = "0.5"

    filter_analysistypes = set(["file","static"])

    malicious_tlds_file = os.path.join(CUCKOO_ROOT, "data/malicioustlds.txt")

    dnsbl_servers = [
        "zen.spamhaus.org",
        "dnsbl.sorbs.net",
        "bl.spamcop.net",
        "cbl.abuseat.org",
        "b.barracudacentral.org",
        "dnsbl-1.uceprotect.net",
        "dnsbl-2.uceprotect.net",
        "dnsbl-3.uceprotect.net",
        "dnsbl.dronebl.org",
        "noptr.spamrats.com",
        "multi.surbl.org",
        "psbl.surriel.com",
        "dnsbl.invaluement.com",
        "dyna.spamrats.com",
        "spam.spamrats.com",
        "dul.dnsbl.sorbs.net",
        "dynip.rothen.com",
        "spamsources.fabel.dk",
        "truncate.gbudb.net",
        "db.wpbl.info",
        "dnsbl.zapbl.net",
        "combined.rbl.msrbl.net",
        "tor.dan.me.uk",
        "relays.nether.net",
        "rbl.efnetrbl.org",
        "bl.kundenserver.de",
        "rbl.interserver.net",
        "rbl.rbldns.ru",
        "all.rbl.jp",
        "sbl.spamhaus.org",
        "xbl.spamhaus.org",
        "pbl.spamhaus.org",
        "dnsbl-4.uceprotect.net",
        "dnsbl-5.uceprotect.net",
        "dnsbl-6.uceprotect.net",
        "spamrbl.imp.ch",
        "bogons.cymru.com",
        "rbl.realtimeblacklist.com",
        "http.dnsbl.sorbs.net",
    ]
    
    def __init__(self, *args, **kwargs):
        super(PDF_Annot_URLs_Checker, self).__init__(*args, **kwargs)
        self.malicious_tlds = self.load_malicious_tlds()

    def load_malicious_tlds(self):
        malicious_tlds = set()
        with open(self.malicious_tlds_file, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("."):
                    malicious_tlds.add(line)
        return malicious_tlds

    def run(self):
        found_malicious_extension = False
        found_malicious_domain = False
        found_domain_only = False
        found_blacklist_ip = False
        suspect = False

        if "PDF" in self.results["target"]["file"].get("type", ""):
            if "Annot_URLs" in self.results["target"]["file"]["pdf"]:
                for entry in self.results["target"]["file"]["pdf"]["Annot_URLs"]:
                    entry_lower = entry.lower()
                    self.data.append({"url": entry})
                    if entry_lower.endswith((".exe", ".zip", ".rar", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1", ".sh")) \
                            and not entry_lower.startswith("mailto:"):
                        found_malicious_extension = True

                    if entry_lower.startswith("http://") or entry_lower.startswith("https://"):
                        domain_start = entry_lower.find("//") + 2
                        domain_end = entry_lower.find("/", domain_start)
                        if domain_end == -1:
                            domain = entry_lower[domain_start:]
                        else:
                            domain = entry_lower[domain_start:domain_end]

                        for malicious_tld in self.malicious_tlds:
                            if domain.endswith(malicious_tld):
                                found_malicious_domain = True
                                break
                        else:
                            # If no malicious TLDs detected, set found_domain_only to True
                            targets = extract_domains(entry_lower)
                            for target in targets:
                                blacklisted_server, server = is_blacklisted(target, self.dnsbl_servers)
                                if blacklisted_server:
                                    found_blacklist_ip = True
                                    self.data.append({"blacklisted": f"The domain or IP address {target} is blacklisted on the following server: {server}  "})
                                    #break # Stop checking once blacklisted IP is found                                    
                                    #print ( blacklisted_server)
                                #else:
                                #    print(f"The domain or IP address {target} is not blacklisted.")
                            

            if found_malicious_domain or found_malicious_extension or found_blacklist_ip :
                self.severity = 6
                self.description = "The PDF contains a Malicious Link Annotation"
                suspect = True
            elif found_domain_only:
                self.severity = 2
                self.description = "The PDF contains a Link Annotation"
                suspect = True

        return suspect
