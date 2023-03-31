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

class JSAtob(Signature):
    name = "JS_atob_detected"
    description = "JS atob Detected, file is obfuscated"
    severity = 2
    confidence = 70
    categories = ["evasion","phishing", "static"]
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
        
class URLDecode(Signature):
    name = "JS_decode_detected"
    description = "JS decode Detected, file is obfuscated"
    severity = 2
    confidence = 70
    categories = ["evasion","phishing", "static"]
    authors = ["Yasin Tas",  "Eye Security"]
    enabled = True
    minimum = "1.2"
    ttps = ["T1140"]  # MITRE v6
    ttps += ["T1566.001"]  # MITRE v6,7,8
    mbcs = ["C0029.003"]  # micro-behaviour

    def run(self):
        if self.results["info"]["package"] == "edge" or self.results["info"]["package"] == "html":
            data =  self.results['target']['file']['data']
            if "decodeURIComponent" in data:
                return True

