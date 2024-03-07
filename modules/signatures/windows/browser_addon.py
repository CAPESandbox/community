# Copyright (C) 2015 Kevin Ross
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


class BrowserAddon(Signature):
    name = "browser_addon"
    description = "Installs a browser addon or extension"
    severity = 2
    categories = ["browser"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    ttps = ["T1112", "T1176"]  # MITRE v6,7,8
    mbcs = ["OB0012", "E1112"]
    mbcs += ["OC0008", "C0036", "C0036.001"]  # micro-behaviour

    def run(self):
        reg_indicators = [
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Internet\\ Explorer\\\\Toolbar\\\\.*",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Mozilla\\\\Firefox\\\\Extensions\\\\.*",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?MozillaPlugins\\\\.*",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Google\\\\Chrome\\\\Extensions\\\\.*",
        ]
        whitelist = [
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Internet\\ Explorer\\\\Toolbar\\\\Locked$",
        ]
        found = False
        for indicator in reg_indicators:
            reg_match = self.check_write_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                for match in reg_match:
                    addit = True
                    for white in whitelist:
                        if not re.match(white, match, re.IGNORECASE):
                            addit = False
                            break
                    if addit:
                        self.data.append({"regkey": match})
                        found = True
        return found


class ChromiumBrowserExtensionDirectory(Signature):
    name = "chromium_browser_extension_directory"
    description = "Loads Chromium browser extension from directory"
    severity = 3
    confidence = 50
    categories = ["browser", "infostealer"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1176"]
    references = ["https://www.mandiant.com/resources/blog/lnk-between-browsers"]

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "--load-extension=" in lower:
                ret = True
                self.data.append({"command": cmdline})

        return ret
