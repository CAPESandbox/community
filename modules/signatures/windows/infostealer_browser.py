# Copyright (C) 2012-2015 Claudio "nex" Guarnieri (@botherder), Optiv, Inc. (brad.spengler@optiv.com)
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


class BrowserStealer(Signature):
    name = "infostealer_browser"
    description = "Steals private information from local Internet browsers"
    severity = 3
    confidence = 30
    categories = ["infostealer"]
    authors = ["nex", "Optiv"]
    minimum = "1.2"
    evented = True
    ttps = ["T1081", "T1503"]  # MITRE v6
    ttps += ["T1003", "T1005"]  # MITRE v6,7,8
    ttps += ["T1552", "T1552.001", "T1555", "T1555.003"]  # MITRE v7,8
    mbcs = ["OB0005"]
    mbcs += ["OC0001", "C0051"]  # micro-behaviour

    filter_apinames = set(["NtQueryAttributesFile", "CopyFileA", "CopyFileW", "CopyFileExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.filematches = set()
        self.saw_stealer = False
        self.indicators = [
            # Firefox
            re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\signons\.sqlite$", re.I),
            re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\cookies\.sqlite$", re.I),
            re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\secmod\.db$", re.I),
            re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\cert8\.db$", re.I),
            re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\key3\.db$", re.I),
            re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\places\.sqlite$", re.I),
            re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\logins\.json$", re.I),
            re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\formhistory\.sqlite$", re.I),

            # Internet Explorer/Edge
            re.compile(".*\\\\History\\\\History.IE5\\\\index\.dat$", re.I),
            re.compile(".*\\\\Cookies\\\\.*", re.I),
            re.compile(".*\\\\Temporary Internet Files\\\\Content.IE5\\\\index\.dat$", re.I),
            re.compile(".*\\\\Microsoft\\\\Edge\\\\User\\ Data\\\\Default\\\\.*", re.I),

            # Google Chrome
            re.compile(".*\\\\Application Data\\\\Google\\\\Chrome\\\\.*", re.I),
            re.compile(".*\\\\Local\\\\Google\\\\Chrome\\\\User\\ Data\\\\Default\\\\.*", re.I),
            re.compile(".*\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User\\ Data\\\\Default\\\\.*", re.I),

            # Chromium-based Browsers
            re.compile(".*\\\\Application Data\\\\Chromium\\\\.*", re.I),
            re.compile(".*\\\\AppData\\\\Local\\\\Chromium\\\\.*", re.I),
            re.compile(".*\\\\Application Data\\\\ChromePlus\\\\.*", re.I),
            re.compile(".*\\\\AppData\\\\Local\\\\MapleStudio\\\\ChromePlus\\\\.*", re.I),
            re.compile(".*\\\\Application Data\\\\Nichrome\\\\.*", re.I),
            re.compile(".*\\\\Application Data\\\\Bromium\\\\.*", re.I),
            re.compile(".*\\\\Application Data\\\\RockMelt\\\\.*", re.I),
            re.compile(".*\\\\Application Data\\\\Flock\\\\.*", re.I),
            re.compile(".*\\\\AppData\\\\Local\\\\Flock\\\\.*", re.I),
            re.compile(".*\\\\Application Data\\\\Comodo\\\\Dragon\\\\.*", re.I),
            re.compile(".*\\\\AppData\\\\Local\\\\Comodo\\\\Dragon\\\\.*", re.I),
            re.compile(".*\\\\BraveSoftware\\\\Brave-Browser\\\\User\\ Data\\\\Default\\\\.*", re.I),

            # Opera
            re.compile(".*\\\\Application Data\\\\Opera\\\\.*", re.I),
            re.compile(".*\\\\AppData\\\\Roaming\\\\Opera\\\\Opera\\\\.*", re.I),
            re.compile(".*\\\\AppData\\\\Roaming\\\\Opera Software\\\\Opera Stable\\\\.*", re.I),

            # Safari
            re.compile(".*\\\\Apple Computer\\\\Safari\\\\WebpageIcons\.db$", re.I),
            re.compile(".*\\\\Apple Computer\\\\Safari\\\\History\.db$", re.I),
            re.compile(".*\\\\Apple Computer\\\\Safari\\\\LastSession\.plist$", re.I),

            # Others
            re.compile(".*\\\\AppData\\\\Local\\\\Spark\\\\User\\ Data\\\\Default\\\\.*", re.I),
            re.compile(".*\\\\AppData\\\\Local\\\\Nichrome\\\\User\\ Data\\\\Default\\\\.*", re.I),
            re.compile(".*\\\\AppData\\\\Local\\\\Titan Browser\\\\User\\ Data\\\\Default\\\\.*", re.I),
            re.compile(".*\\\\AppData\\\\Local\\\\Rockmelt\\\\User\\ Data\\\\Default\\\\.*", re.I),
            re.compile(".*\\\\AppData\\\\Local\\\\Torch\\\\User\\ Data\\\\Default\\\\.*", re.I),
            re.compile(".*\\\\AppData\\\\Local\\\\.*\\\\YandexBrowser\\\\User\\ Data\\\\Default\\\\.*", re.I),
        ]

    def on_call(self, call, process):
        # If the current process appears to be a browser, continue.
        # TODO: implement better checks here -- the malware can be named whatever it wants or can
        # inject into browser processes
        if process["process_name"].lower() in ("iexplore.exe", "firefox.exe", "chrome.exe"):
            return None

        filename = None
        if call["api"] == "NtQueryAttributesFile":
            filename = self.get_argument(call, "FileName")
        if not filename:
            return None

        for indicator in self.indicators:
            if indicator.match(filename):
                self.filematches.add(filename)
                if self.pid:
                    self.mark_call()
                self.saw_stealer = True

    def on_complete(self):
        for file in self.filematches:
            self.data.append({"file": file})
        return self.saw_stealer
