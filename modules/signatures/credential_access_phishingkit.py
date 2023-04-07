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

class HTMLPhisher_0(Signature):
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
            if "strings" not in self.results["target"]["file"] or self.results["target"]["file"]["strings"] == []:
                return False
            strings =  self.results["target"]["file"]["strings"]
            regex_decodedURL = r"unescape\( \'([^&]+?)\' \) \);</script>"
            data = ''.join(strings)
            decodeString = re.search(regex_decodedURL,data)
            if decodeString:
                self.description = "File obfuscation detected, with url encoding"
                decodeString = decodeString.group(1)
                decoded_string = Chepy(decodeString).url_decode().url_decode().o
                regex_user = r'var encoded_string = "([^&]+?)"'
                regex_url = r"var url =  window.atob\('([^&]+?)'\)"
                regex_post_url = r'window\.location\.href="([^&]+.*)";'
                user = re.search(regex_user,decoded_string)
                url = re.search(regex_url,decoded_string)
                post_url = re.search(regex_post_url,decoded_string)
                if user and url and post_url:
                    self.weight = 3
                    self.families = ["HTMLPhisher_2023"]
                    self.description = "Phishing kit detected, extracted config from sample"
                    self.data.append({"url": base64.b64decode(url.group(1)).decode("utf-8")})
                    self.data.append({"user": user.group(1)})
                    self.data.append({"post_url": post_url.group(1)})
                    return True
        return False

class HTMLPhisher_1(Signature):
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
            if "strings" not in self.results["target"]["file"] or self.results["target"]["file"]["strings"] == []:
                return False
            strings = self.results["target"]["file"]["strings"]
            data = ''.join(strings)
            regex_decoded = r"unescape\(\'([^&]+?)\'\)\); </script>"
            decodeString = re.search(regex_decoded,data)
            if decodeString:
                decodeString = decodeString.group(1)
                decoded_string = Chepy(decodeString).url_decode().url_decode().o
                self.description = "File obfuscation detected, with url encoding"
                regex_user = r'value="([^&]+?)"'
                regex_url = r"url: '([^&]+?)',"
                user = re.search(regex_user,decoded_string)
                url = re.search(regex_url,decoded_string)
                if user and url:
                    self.weight = 3
                    self.families = ["HTMLPhisher_2023"]
                    self.description = "Phishing kit detected, extracted config from sample"
                    self.data.append({"url": url.group(1)})
                    self.data.append({"user": user.group(1)})
                    return True
        return False
                
