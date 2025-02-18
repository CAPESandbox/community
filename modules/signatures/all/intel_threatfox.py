# Copyright (C) 2025 Kevin Ross
# Copyright (C) 2025 ThreatFox https://raw.githubusercontent.com/abusech/ThreatFox/refs/heads/main/threatfox_search_ioc.py
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

from lib.cuckoo.common.abstracts import Signature
from lib.cuckoo.common.utils import add_family_detection


class ThreatFox(Signature):
    name = "threatfox"
    description = "Threatfox indicator matched"
    severity = 3
    categories = ["network"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = []

    def ioc_lookup(self, searchterm):
        jsondict = self.check_threatfox(searchterm)
        if not jsondict:
            return

        iocdata = jsondict["data"][0]
        if iocdata and iocdata != "Y":
            self.data.append({"ioc_match": iocdata})
            if iocdata["threat_type"] == "botnet_cc" and "Unknown malware" != iocdata["malware_printable"]:
                add_family_detection(self.results, iocdata["malware_printable"], "Behavior", searchterm)
            self.ret = True
            if iocdata["threat_type"] == "botnet_cc":
                self.ttps.append("TA0011")
            if iocdata["threat_type"] == "payload_delivery":
                self.ttps.append("T1189")

    def run(self):
        self.ret = False

        for host in self.results.get("network", {}).get("hosts", []):
            ip = host["ip"]
            if host.get("ports", []):
                for port in host.get("ports", []):
                    searchterm = f"{ip}:{port}"
                    self.ioc_lookup(searchterm)
            else:
                self.ioc_lookup(ip)

            # ToDo do we want to check ports here too?
            if host.get("hostname"):
                self.ioc_lookup(host["hostname"])

        return self.ret
