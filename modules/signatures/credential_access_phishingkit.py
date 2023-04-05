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

try:
    from chepy import Chepy
except ImportError:
    raise ImportError("Please install chepy")

import base64

class PhishHTMLGenahtml(Signature):
    name = "phishing_kit_detected"
    description = "Phishing Kit Detected, sample is trying to harvest credentials"
    severity = 3
    confidence = 100
    categories = ["credential_access","evasion","infostealer","phishing", "static"]
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
                    self.description = "Phishing kit detected, extracted config from sample"
                    self.families = ["Phish:HTML/Gen.a!html"]
                    return True
                else:
                    return True
        
        return False

class PhishHTMLGenbhtml(Signature):
    name = "phishing_kit_detected"
    description = "Phishing Kit Detected, sample is trying to harvest credentials"
    severity = 3
    confidence = 100
    categories = ["credential_access","evasion","infostealer","phishing", "static"]
    authors = ["Yasin Tas",  "Eye Security"]
    enabled = True
    minimum = "1.2"
    ttps = ["T1111", "T1193", "T1140"]  # MITRE v6
    ttps += ["T1566.001"]  # MITRE v6,7,8
    ttps += ["T1606"]  # MITRE v7,8
    mbcs = ["C0029.003"]  # micro-behaviour

    def run(self):
        if self.results["info"]["package"] == "edge" or self.results["info"]["package"] == "html":
            strings = self.results["target"]['file']["strings"]
            data = ''.join(strings)
            regex_decoded = r"unescape\(\'([^&]+?)\'\)\); </script>"
            decodeString = re.search(regex_decoded,data)
            if decodeString:
                decodeString = decodeString.group(1)
                self.weight = 1
                decoded_string = Chepy(decodeString).url_decode().url_decode().o
                self.description = "File obfuscation detected with url decode"
                regex_user = r'value="([^&]+?)"'
                regex_url = r"url: '([^&]+?)',"
                user = re.search(regex_user,decoded_string)
                url = re.search(regex_url,decoded_string)
                if user and url:
                    self.weight = 3
                    self.families = ["Phish:HTML/Gen.b!html"]
                    self.description = "Phishing kit detected, extracted config from sample"
                    self.data.append({"url": url.group(1)})
                    self.data.append({"user": user.group(1)})
                    return True
        return False
                
class PhishHTMLGenchtml(Signature):
    name = "phishing_kit_detected"
    description = "Phishing Kit Detected, sample is trying to harvest credentials"
    severity = 3
    confidence = 100
    categories = ["credential_access","infostealer","phishing", "static"]
    authors = ["Yasin Tas",  "Eye Security"]
    enabled = True
    minimum = "1.2"
    ttps = ["T1111", "T1193", "T1140"]  # MITRE v6
    ttps += ["T1566.001"]  # MITRE v6,7,8
    ttps += ["T1606"]  # MITRE v7,8

    def run(self):
        if self.results["info"]["package"] == "edge" or self.results["info"]["package"] == "html":
            data =  self.results['target']['file']['data']
            url_regex = r"<form method=\"post\" action=\"([^&]+?)\">"
            user_regex = r"<input name=\"login\" type=\"hidden\" value=\"([^&]+?)\">"
            url = re.search(url_regex,str(data))
            user = re.search(user_regex,str(data))
            if url and user:
                self.weight = 1
                self.description = "Phishing kit detected, extracted config from sample"
                self.families = ["Phish:HTML/Gen.c!html"]
                self.data.append({"url": url})
                self.data.append({"user": user})
                return True
            
class PhishHTMLGendhtml(Signature):
    name = "phishing_kit_detected"
    description = "Phishing Kit Detected, sample is trying to harvest credentials"
    severity = 3
    confidence = 100
    categories = ["credential_access","infostealer","phishing", "static"]
    authors = ["Yasin Tas",  "Eye Security"]
    enabled = True
    minimum = "1.2"
    ttps = ["T1111", "T1193", "T1140"]  # MITRE v6
    ttps += ["T1566.001"]  # MITRE v6,7,8
    ttps += ["T1606"]  # MITRE v7,8

    def run(self):
        if self.results["info"]["package"] == "edge" or self.results["info"]["package"] == "html":
            data =  self.results['target']['file']['data']
            user = re.search(r"var eml = \"([^&]+?)\";",str(data))
            url_regex = re.search(r'window.atob\(\'([^&]+?)\"\)}`',str(data))
            url_decoded = Chepy(url_regex).base64_decode().o
            if user and url_regex:
                self.weight = 1
                self.description = "Phishing kit detected, extracted config from sample"
                self.families = ["Phish:HTML/Gen.d!html"]
                self.data.append({"url": url_decoded})
                self.data.append({"user": user})
                return True
            
class PhishHTMLGenehtml(Signature):
    name = "phishing_kit_detected"
    description = "Phishing Kit Detected, sample is trying to harvest credentials"
    severity = 3
    confidence = 100
    categories = ["credential_access","infostealer","phishing", "static"]
    authors = ["Yasin Tas",  "Eye Security"]
    enabled = True
    minimum = "1.2"
    ttps = ["T1111", "T1193", "T1140"]  # MITRE v6
    ttps += ["T1566.001"]  # MITRE v6,7,8
    ttps += ["T1606"]  # MITRE v7,8

    def run(self):
        if self.results["info"]["package"] == "edge" or self.results["info"]["package"] == "html":
            data =  self.results['target']['file']['data']
            regex_user = r'data-emailValue="([^&]+?)"'