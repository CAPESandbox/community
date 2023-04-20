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
    
import re

class htmlBody(Signature):
    name = "suspicious_html_body"
    description = "Sample contains suspicious HTML body"
    severity = 1
    confidence = 80
    categories = ["phishing", "static"]
    authors = ["Yasin Tas",  "Eye Security"]
    references = [
    "https://securelist.com/phishing-kit-market-whats-inside-off-the-shelf-phishing-packages/106149/",
    "https://socradar.io/what-is-a-phishing-kit/"
    "https://github.com/SteveD3/kit_hunter/tree/master/tag_files"
    ]
    enabled = True
    evented = True
    minimum = "1.2"
    ttps = ["T1566.001"]  # MITRE v6,7,8
    mbcs = ["C0029.003"]  # micro-behaviour


    
        
    def run(self):
        packages = ['html', 'edge', 'chrome', 'firefox']
        indicators = [
                'password',
                'email',
                'username',
                'encoded_string',
                'url',
                '// remove email, and put ur mailer code',
            ]
        if self.results["info"]["package"] in packages:
            if "strings" in self.results["target"]["file"]:
                strings = self.results["target"]["file"]["strings"]
                data = ''.join(strings)
                for indicator in indicators:
                    if indicator in data:
                        self.add_match(None, 'string', f'Found string {indicator} in HTML body')
        return self.has_matches()


class htmlTitle(Signature):
    name = "suspicious_html_title"
    description = "Sample contains suspicious HTML title"
    severity = 1
    confidence = 80
    categories = ["phishing", "static"]
    authors = ["Yasin Tas",  "Eye Security"]
    references = [
    "https://securelist.com/phishing-kit-market-whats-inside-off-the-shelf-phishing-packages/106149/",
    "https://socradar.io/what-is-a-phishing-kit/"
    "https://github.com/SteveD3/kit_hunter/tree/master/tag_files"
    ]
    enabled = True
    minimum = "1.2"
    ttps = ["T1566.001"]  # MITRE v6,7,8
    mbcs = ["C0029.003"]  # micro-behaviour
    
    def run(self):
        
        packages = ['html', 'edge', 'chrome', 'firefox']
        indicators = [
            'Please wait',
            'Sign in',
                    ]
        
        title_regex = re.compile(r'<\s*title[^>]*>(.*?)<\/\s*title\s*>')

        if self.results["info"]["package"] in packages:
            if "strings" in self.results["target"]["file"]:
                strings = self.results["target"]["file"]["strings"]
                data = ''.join(strings)
                title = title_regex.search(data)
                if not title:
                    self.description = "Sample contains empty HTML title"
                    self.add_match(None, 'string', 'Empty HTML title')
                else:
                    for indicator in indicators:
                        if indicator in title.group(1):
                            self.add_match(None, 'string', f'Found {indicator} in HTML title')
                            
            return self.has_matches()

class suspiciousHTMLname(Signature):
    name = "suspicious_html_name"
    description = "Sample contains suspicious HTML name"
    severity = 1
    confidence = 80
    categories = ["phishing", "static"]
    authors = ["Yasin Tas",  "Eye Security"]
    references = [
    "https://securelist.com/phishing-kit-market-whats-inside-off-the-shelf-phishing-packages/106149/",
    "https://socradar.io/what-is-a-phishing-kit/"
    "https://github.com/SteveD3/kit_hunter/tree/master/tag_files"
    ]
    enabled = False
    minimum = "1.2"
    ttps = ["T1566.001"]  # MITRE v6,7,8
    mbcs = ["C0029.003"]  # micro-behaviour
    
    def run(self):
        packages = ['html', 'edge', 'chrome', 'firefox']
        indicators = [
            'payment',
            'remittence',
            'invoice',
            'inv',
            'voicemail',
            'remit',
            'voice',
                      ]
        
        if self.results["info"]["package"] in packages:
            name = self.results["target"]["file"]["name"]
            lower = name.lower()
            for indicator in indicators:
                if indicator in lower:
                    self.add_match(None, 'string', f'Found {indicator} in HTML name')
        return self.has_matches()