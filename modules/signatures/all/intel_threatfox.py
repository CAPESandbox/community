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

import requests
import urllib3
import json

from lib.cuckoo.common.abstracts import Signature

class ThreatFox(Signature):
    name = "threatfox"
    description = "Threatfox indicator matched"
    severity = 3
    categories = ["network"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = []

    def run(self):
        apikey = ""
        ret = False
  
        #for host in self.results.get("network", {}).get("hosts", []):
        #   ipaddress = host["ip"]
        #    if ipaddress:
        #       searchterm = ipaddress             

        # Perform ThreatFox lookup for DNS results

        if apikey:        
            for dns in self.results.get("network", {}).get("domains", []):
                query = dns["domain"]

                if query:
                    searchterm = query
  
                if searchterm:
                    headers = {"Auth-Key" : apikey}
                    data = {
                       'query':            'search_ioc',
                       'search_term':      searchterm
                    }

                    pool = urllib3.HTTPSConnectionPool('threatfox-api.abuse.ch', port=443, maxsize=50, headers=headers)

                    json_data = json.dumps(data)
                    response = pool.request("POST", "/api/v1/", body=json_data)

                    # Parse JSON and extract matches           
                    jsondata = json.dumps(response.json())
                    jsondict = json.loads(jsondata)
                    
                    iocdata = jsondict['data'][0]
                    if iocdata and iocdata != "Y":
                        self.data.append({"ioc_match": iocdata })
                                 
                        if iocdata['threat_type'] == "botnet_cc" and "Unknown malware" != iocdata['malware_printable']:                 
                            self.families.append(iocdata['malware_printable'])
                        ret = True

                        if iocdata['threat_type'] == "botnet_cc":
                            self.ttps.append("TA0011")
                        if iocdata['threat_type'] == "payload_delivery":
                            self.ttps.append("T1189")

        return ret
