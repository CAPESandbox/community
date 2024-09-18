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


class suspiciousHRML_Body(Signature):
    name = "suspicious_html_body"
    description = "Sample contains suspicious HTML body"
    severity = 3
    confidence = 100
    categories = ["phishing", "static"]
    authors = ["Yasin Tas", "Eye Security"]
    references = [
        "https://securelist.com/phishing-kit-market-whats-inside-off-the-shelf-phishing-packages/106149/",
        "https://github.com/0xDanielLopez/phishing_kits", "https://socradar.io/what-is-a-phishing-kit/",
        "https://github.com/SteveD3/kit_hunter/tree/master/tag_files",
    ]
    enabled = True
    minimum = "1.2"
    ttps = ["T1566.001"]  # MITRE v6,7,8
    mbcs = ["C0029.003"]  # micro-behaviour

    def run(self):
        packages = ["html", "edge", "chrome", "firefox"]
        indicators = [
            "encoded_string",
            "// remove email, and put ur mailer code",
            "eval",
            "atob",
            "btoa",
            "decodeURIComponent",
            "cardnumber",
            "expirationdate",
            "securitycode",
            "api.telegram.org",
            "YOUR_BOT_TOKEN",
            "YOUR_CHANNEL_ID",
            "telegramApiUrl",
            "1TAO UY1 EMPR3",
            "createElement(\"script\")"
        ]
        has_match = False
        if self.results["info"]["package"] in packages:
            if "strings" in self.results["target"]["file"]:
                strings = self.results["target"]["file"]["strings"]
                data = "".join(strings) if strings else self.results["target"]["file"]["data"]
                for indicator in indicators:
                    if indicator in data:
                        self.data.append({"indicator": indicator})
                        has_match = True
        return has_match


class suspiciousHTML_Title(Signature):
    name = "suspicious_html_title"
    description = "Sample contains suspicious HTML title"
    severity = 3
    confidence = 100
    categories = ["phishing", "static"]
    authors = ["Yasin Tas", "Eye Security"]
    references = [
        "https://securelist.com/phishing-kit-market-whats-inside-off-the-shelf-phishing-packages/106149/",
        "https://socradar.io/what-is-a-phishing-kit/" "https://github.com/SteveD3/kit_hunter/tree/master/tag_files",
    ]
    enabled = True
    minimum = "1.2"
    ttps = ["T1566.001"]  # MITRE v6,7,8
    mbcs = ["C0029.003"]  # micro-behaviour

    def run(self):

        packages = ["html", "edge", "chrome", "firefox"]
        indicators = [
            "Please wait",
            "Sign in",
            "<title></title>",  # Empty title
            "Redirecting",
        ]

        title_regex = re.compile(r"<\s*title[^>]*>(.*?)<\/\s*title\s*>")
        has_match = False

        if self.results["info"]["package"] in packages:
            if "strings" in self.results["target"]["file"]:
                strings = self.results["target"]["file"]["strings"]
                data = "".join(strings) if strings else self.results["target"]["file"]["data"]
                title = title_regex.search(data)
                if not title:
                    self.data.append({"indicator": "empty", "location": "title"})
                    has_match = True
                else:
                    for indicator in indicators:
                        if indicator in title.group(1):
                            self.data.append({"indicator": indicator, "location": "title"})
                            has_match = True

        return has_match


class suspiciousHTML_Filename(Signature):
    name = "suspicious_html_name"
    description = "Sample contains suspicious HTML name"
    severity = 3
    confidence = 80
    categories = ["phishing", "static"]
    authors = ["Yasin Tas", "Eye Security"]
    references = [
        "https://securelist.com/phishing-kit-market-whats-inside-off-the-shelf-phishing-packages/106149/",
        "https://socradar.io/what-is-a-phishing-kit/" "https://github.com/SteveD3/kit_hunter/tree/master/tag_files",
    ]
    enabled = True
    minimum = "1.2"
    ttps = ["T1566.001"]  # MITRE v6,7,8
    mbcs = ["C0029.003"]  # micro-behaviour

    def run(self):
        packages = ["html", "edge", "chrome", "firefox"]
        indicators = [
            "payment",
            "remittence",
            "remmitance ",
            "invoice",
            "inv",
            "voicemail",
            "remit",
            "voice",
            "statement",
            "RECEIPT",
            "delivery",
            "company",
            "agreements",
            "biometrics",
            "audio",
            "social",
            "security",
            "credit",
            "confidential",
            "transfer",
            "funds",
            "coin",
            "play",
            "recording",
        ]
        has_match = False

        if self.results["info"]["package"] in packages:
            name = self.results["target"]["file"]["name"]
            lower = name.lower()
            for indicator in indicators:
                if indicator in lower:
                    self.data.append({"indicator": indicator, 'location': 'filename'})
                    has_match = True
        return has_match
