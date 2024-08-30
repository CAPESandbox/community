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

import re

from lib.cuckoo.common.abstracts import Signature
import base64
from urllib.parse import unquote


class HTMLPhisher_0(Signature):
    name = "phishing_kit_detected_0"
    description = "Phishing Kit Detected, sample is trying to harvest credentials"
    severity = 3
    confidence = 100
    categories = ["credential_access", "evasion", "infostealer", "phishing", "static"]
    authors = ["Yasin Tas", "Eye Security"]
    references = [
        "https://securelist.com/phishing-kit-market-whats-inside-off-the-shelf-phishing-packages/106149/",
        "https://socradar.io/what-is-a-phishing-kit/" "https://github.com/SteveD3/kit_hunter/tree/master/tag_files",
    ]
    enabled = True
    minimum = "1.2"
    ttps = ["T1111", "T1193", "T1140"]  # MITRE v6
    ttps += ["T1566.001"]  # MITRE v6,7,8
    ttps += ["T1606"]  # MITRE v7,8
    mbcs = ["C0029.003"]  # micro-behaviour
    packages = ["html", "edge", "chrome", "firefox"]

    def run(self):
        has_match = False
        if self.results["info"]["package"] in self.packages:
            strings = self.results["target"]["file"]["strings"]
            regex_decodedURL = r"unescape\(\s*\"([^&]+?)\"\s*\)"
            data = "".join(strings) if strings else self.results["target"]["file"]["data"]
            decodeString = re.search(regex_decodedURL, data)
            if decodeString:
                has_match = True
                self.description = "File obfuscation detected, with url encoding"
                decoded = decodeString.group(1)
                decoded_string = unquote(decoded, "utf-8")
                regex_user = r"var\s*encoded_string\s*=\s*['\"]([^&]+?)\['\"]"
                regex_url = r"window.atob\(['\"]([^&]+?)['\"]\)"
                regex_post_url = r'window\.location\.href\s*=\s*"([^&]+.*)"'
                user = re.search(regex_user, decoded_string)
                url = re.search(regex_url, decoded_string)
                post_url = re.search(regex_post_url, decoded_string)
                if user or url or post_url:
                    self.weight = 3
                    self.families = ["HTMLPhisher_2023"]
                    self.description = "Phishing kit detected, extracted config from sample"
                    if url:
                        self.data.append({"url": base64.b64decode(url.group(1)).decode("utf-8")})
                    if user:
                        self.data.append({"user": user.group(1)})
                    if post_url:
                        self.data.append({"post_url": post_url.group(1)})
        return has_match

class HTMLPhisher_1(Signature):
    name = "phishing_kit_detected_1"
    description = "Phishing Kit Detected, sample is trying to harvest credentials"
    severity = 3
    confidence = 100
    categories = ["credential_access", "evasion", "infostealer", "phishing", "static"]
    authors = ["Yasin Tas", "Eye Security"]
    references = [
        "https://securelist.com/phishing-kit-market-whats-inside-off-the-shelf-phishing-packages/106149/",
        "https://socradar.io/what-is-a-phishing-kit/" "https://github.com/SteveD3/kit_hunter/tree/master/tag_files",
    ]
    enabled = True
    minimum = "1.2"
    ttps = ["T1111", "T1193", "T1140"]  # MITRE v6
    ttps += ["T1566.001"]  # MITRE v6,7,8
    ttps += ["T1606"]  # MITRE v7,8
    mbcs = ["C0029.003"]  # micro-behaviour
    packages = ["html", "edge", "chrome", "firefox"]

    def run(self):
        has_match = False

        if self.results["info"]["package"] in self.packages:
            strings = self.results["target"]["file"]["strings"]
            data = "".join(strings) if strings else self.results["target"]["file"]["data"]
            regex_decoded = [
                r"unescape\(\'([^&]+?)\'\)\);",
                r"unescape\( \'([^&]+?)\' \) \);",
                r"unescape\(\'([^&]+?)\'\) \);",
                r"unescape\( \'([^&]+?)\'\) \);",
                r"unescape\(\s*\['\"]([^&]+?)\['\"]\s*\)",
            ]
            for regex in regex_decoded:
                decodeString = re.search(regex, data)
                if decodeString:
                    has_match = True
                    decodeString = decodeString.group(1)
                    decoded_string = unquote(decodeString, "utf-8")
                    self.description = "File obfuscation detected, with url encoding"
                    regex_user = r"value\s*=\s*['\"]\s*([^&]+?)['\"]"
                    regex_url = r"url\s*:\s*['\"]([^&]+?)['\"]"
                    user = re.search(regex_user, decoded_string)
                    url = re.search(regex_url, decoded_string)
                    if user or url:
                        self.weight = 3
                        self.families = ["HTMLPhisher_2023"]
                        self.description = "Phishing kit detected, extracted config from sample"
                        if url:
                            self.data.append({"url": url.group(1)})
                        if user:
                            self.data.append({"user": user.group(1)})
                    else:
                        self.weight = 2
                        self.data.append({"obfuscated_value": decoded_string})
        return has_match


class HTMLPhisher_2(Signature):
    name = "phishing_kit_detected_2"
    description = "Phishing Kit Detected, sample is trying to harvest credentials"
    severity = 3
    confidence = 100
    categories = ["credential_access", "evasion", "infostealer", "phishing", "static"]
    authors = ["Yasin Tas", "Eye Security"]
    references = [
        "https://securelist.com/phishing-kit-market-whats-inside-off-the-shelf-phishing-packages/106149/",
        "https://socradar.io/what-is-a-phishing-kit/" "https://github.com/SteveD3/kit_hunter/tree/master/tag_files",
    ]
    enabled = True
    minimum = "1.2"
    ttps = ["T1111", "T1193", "T1140"]  # MITRE v6
    ttps += ["T1566.001"]  # MITRE v6,7,8
    ttps += ["T1606"]  # MITRE v7,8
    mbcs = ["C0029.003"]  # micro-behaviour

    def run(self):
        has_match = False
        packages = ["html", "edge", "chrome", "firefox"]

        if self.results["info"]["package"] in packages:
            strings = self.results["target"]["file"]["strings"]
            data = "".join(strings) if strings else self.results["target"]["file"]["data"]

            regex_user = r"<input  name=\"login\" type=\"email\" value=\"([^&]+?)\" disabled>"
            regex_url = r"<form method=\"post\" action=\"([^&]+?)\">"
            user = re.search(regex_user, data)
            url = re.search(regex_url, data)
            if user or url:
                has_match = True
                self.weight = 3
                self.families = ["HTMLPhisher_2023"]
                self.description = "Phishing kit detected, extracted config from sample"
                if url:
                    self.data.append({"url": url.group(1)})
                if user:
                    self.data.append({"user": user.group(1)})
        return has_match
