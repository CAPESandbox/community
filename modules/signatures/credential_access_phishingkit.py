# Copyright (C) 2023 Eye Security (yasin.tas@eye.security)
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

from lib.cuckoo.common.abstracts import Signature

try:
    import re2 as re
except ImportError:
    import re

import base64

class PhishingKit(Signature):
    name = "phishing_kit_detected"
    description = "Phishing Kit Detected, sample is trying to harvest credentials"
    severity = 3
    confidence = 100
    categories = ["credential_access","evasion","infostealer","phishing", "static"]
    families = ["PhishingKit"]
    authors = ["Yasin Tas",  "Eye Security"]
    enabled = True
    minimum = "1.2"
    ttps = ["T1111", "T1193", "T1140"]  # MITRE v6
    ttps += ["T1566.001"]  # MITRE v6,7,8
    ttps += ["T1606"]  # MITRE v7,8
    mbcs = ["C0029.003"]  # micro-behaviour

    def run(self):

        if self.results["info"]["package"] == "edge" or self.results["info"]["package"] == "html":
            data =  self.results['target']['file']['data']
            regex_base64 = r'value="([^&]+?)"></input>'
            decodeString = re.findall(regex_base64,str(data))
            if decodeString:
                self.weight = 1
                decoded_url = base64.b64decode(decodeString[0])
                self.data.append({"decoded_url": decoded_url})
                decoded_user = base64.b64decode(decodeString[1])
                self.data.append({"decoded_user": decoded_user})
                if decoded_url and decoded_user:
                    self.weight = 2
                    return True
                else:
                    return True
        
        return False

class JSAtob(Signature):
    name = "JS_atob_detected"
    description = "JS atob Detected, file is obfuscated"
    severity = 2
    confidence = 70
    categories = ["evasion","phishing", "static"]
    families = ["PhishingKit"]
    authors = ["Yasin Tas",  "Eye Security"]
    enabled = True
    minimum = "1.2"
    ttps = ["T1140"]  # MITRE v6
    ttps += ["T1566.001"]  # MITRE v6,7,8
    mbcs = ["C0029.003"]  # micro-behaviour

    def run(self):
        if self.results["info"]["package"] == "edge" or self.results["info"]["package"] == "html":
            data =  self.results['target']['file']['data']
            if "atob" in data:
                return True
            
        return False
        
