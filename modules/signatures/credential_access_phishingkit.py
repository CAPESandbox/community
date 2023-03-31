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

try:
    from chepy import Chepy
except ImportError:
    raise ImportError("Please install chepy")

import base64

class PhishingKit0(Signature):
    name = "phishing0_kit_detected"
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
                    self.families = ["PhishingKit-0"]
                    return True
                else:
                    return True
        
        return False

class PhishingKit1(Signature):
    name = "phishing1_kit_detected"
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
            regex_decodedURL = r"unescape\( \'([^&]+?)\' \) \);</script>"
            decodeString = re.search(regex_decodedURL,str(data)).group(0)
            if decodeString:
                self.weight = 1
                decoded_string = Chepy(decodeString).url_decode()
                self.description = "File obfuscation detected with url decode"
                if "atob" in decoded_string:
                    self.weight += 1
                    self.description = "File obfuscation detected with url decode and atob"
                if "encoded_string" in decoded_string:
                    self.weight += 1
                    self.description = "File obfuscation detected with url decode and found encoded_string"
                if "encoded_string" in decoded_string and "atob" in decoded_string:
                    self.weight = 3
                    self.families = ["PhishingKit-1"]
                    user_regex = r"var encoded_string = \"([^&]+?)\";"
                    url_regex = r"window.atob\(\'([^&]+?)\'\)"
                    #this regex can be improved
                    aws_regex = r'window.location.href="([Hh][Tt][Tt][Pp][Ss]?://(.*)+?)'
                    user = re.search(user_regex,decoded_string).group(1)
                    url = re.search(url_regex,decoded_string).group(1)
                    aws = re.search(aws_regex,decoded_string).group(0).replace("window.location.href=\"","")
                    if user and url and aws:
                        self.description = "Phishing kit detected, extracted config from sample"
                        self.data.append({"decoded_url": base64.b64decode(url)})
                        self.data.append({"decoded_user": user})
                        self.data.append({"aws_url": aws})
                        return True
                    return True
        return False
                
class PhishingKit2(Signature):
    name = "phishing2_kit_detected"
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
            user_regex = r"<input  name=\"login\" type=\"hidden\" value=\"([^&]+?)\""
            url = re.search(url_regex,str(data))
            user = re.search(user_regex,str(data))
            if url and user:
                self.weight = 1
                self.description = "Phishing kit detected, extracted config from sample"
                self.families = ["PhishingKit-2"]
                self.data.append({"url": url})
                self.data.append({"user": user})
                return True