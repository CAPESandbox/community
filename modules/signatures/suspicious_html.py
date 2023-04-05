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

class htmlBody(Signature):
    name = "suspicious_html_body"
    description = "Sample contains suspicious HTML body"
    severity = 1
    confidence = 80
    categories = ["phishing", "static"]
    authors = ["Yasin Tas",  "Eye Security"]
    enabled = False
    minimum = "1.2"
    ttps = ["T1566.001"]  # MITRE v6,7,8
    mbcs = ["C0029.003"]  # micro-behaviour
    
    def run(self):
        
        indicators = ['password',
                  'email',
                  'username',
                  ]
        
        if self.results["info"]["package"] == "edge" or self.results["info"]["package"] == "html":
            data =  self.results['target']['file']['data']
            for indicator in indicators:
                if indicator in data:
                    self.data.append({f"Found {indicator} in HTML body"})
                    return True
        return False

class htmlTitle(Signature):
    name = "suspicious_html_title"
    description = "Sample contains suspicious HTML title"
    severity = 1
    confidence = 80
    categories = ["phishing", "static"]
    authors = ["Yasin Tas",  "Eye Security"]
    enabled = False
    minimum = "1.2"
    ttps = ["T1566.001"]  # MITRE v6,7,8
    mbcs = ["C0029.003"]  # micro-behaviour
    
    def run(self):
        
        indicators = ['Sign in to your account',
                    ]
        
        title_regex = re.compile(r'/<title>.*<\/title>/i')

        if self.results["info"]["package"] == "edge" or self.results["info"]["package"] == "html":
            data =  self.results['target']['file']['data']
            for indicator in indicators:
                if indicator in data:
                    self.data.append({f"Found {indicator} in HTML title"})
                    return True
            if title_regex.search(data):
                self.description = "Sample contains empty HTML title"
                return True
        return False

class suspiciousHTMLname(Signature):
    name = "suspicious_html_name"
    description = "Sample contains suspicious HTML name"
    severity = 1
    confidence = 80
    categories = ["phishing", "static"]
    authors = ["Yasin Tas",  "Eye Security"]
    enabled = False
    minimum = "1.2"
    ttps = ["T1566.001"]  # MITRE v6,7,8
    mbcs = ["C0029.003"]  # micro-behaviour
    
    def run(self):
        
        indicators = ['payment',
                      'remittence',
                      'invoice',
                      'inv',
                      'voicemail',
                      'remit',
                      ]
        
        if self.results["info"]["package"] == "edge" or self.results["info"]["package"] == "html":
            name = self.results['target']['file']['name']
            lower = name.lower()
            for indicator in indicators:
                if indicator in lower:
                    self.data.append({f"Found {indicator} in sample name"})
                    return True
        