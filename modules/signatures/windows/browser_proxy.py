# Copyright (C) 2015 Kevin Ross, Optiv, Inc. (brad.spengler@optiv.com)
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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature


class ModifyProxy(Signature):
    name = "modify_proxy"
    description = "Attempts to modify proxy settings"
    severity = 3
    categories = ["browser"]
    authors = ["Kevin Ross", "Optiv"]
    minimum = "1.2"
    ttps = ["T1112"]  # MITRE v6,7,8
    mbcs = ["OB0006", "E1112"]
    mbcs += ["OC0008", "C0036", "C0036.001"]  # micro-behaviour

    filter_analysistypes = set(["file"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.proc_safelist = [
            "acrobat.exe",
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
            "acrord32.exe",
            "acrord64.exe",
            "wordview.exe",
            "adobearm.exe",
            "ai.exe",
        ]
        self.indicators = [
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\ProxyEnable$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\ProxyServer$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\ZoneMap\\ProxyBypass$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\ProxyOverride$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\Wpad\\.*",
        ]
        self.whitelist = [
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\Wpad\\WpadLastNetwork$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\Wpad\\[^\\]*\\WpadDecisionReason$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\Wpad\\[^\\]*\\WpadDecisionTime$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\Wpad\\[^\\]*\\WpadDecision$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\Wpad\\[^\\]*\\WpadNetworkName$",
        ]

    def on_call(self, call, process):
        if process["process_name"].lower() in self.proc_safelist:
            return False
        else:
            for indicator in self.indicators:
                matches = self.check_write_key(pattern=indicator, regex=True, all=True)
                if matches:
                    for match in matches:
                        foundwhite = False
                        for white in self.whitelist:
                            if re.match(white, match, re.IGNORECASE):
                                foundwhite = True
                        if not foundwhite:
                            self.mark_call()
                            return True
