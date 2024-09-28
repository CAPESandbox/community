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
        self.MALICIOUS_ARTIFACTS_THRESHOLD = 3
        self.artifacts_counter = 0
        self.filematches = set()
        self.saw_stealer = False
        self.indicators = [
            # Firefox
            re.compile(r".*\\Mozilla\\Firefox\\Profiles\\.*\\.default\\signons\.sqlite$", re.I),
            re.compile(r".*\\Mozilla\\Firefox\\Profiles\\.*\\.default\\cookies\.sqlite$", re.I),
            re.compile(r".*\\Mozilla\\Firefox\\Profiles\\.*\\.default\\secmod\.db$", re.I),
            re.compile(r".*\\Mozilla\\Firefox\\Profiles\\.*\\.default\\cert8\.db$", re.I),
            re.compile(r".*\\Mozilla\\Firefox\\Profiles\\.*\\.default\\key3\.db$", re.I),
            re.compile(r".*\\Mozilla\\Firefox\\Profiles\\.*\\.default\\places\.sqlite$", re.I),
            re.compile(r".*\\Mozilla\\Firefox\\Profiles\\.*\\.default\\logins\.json$", re.I),
            re.compile(r".*\\Mozilla\\Firefox\\Profiles\\.*\\.default\\formhistory\.sqlite$", re.I),
            # Internet Explorer/Edge
            re.compile(r".*\\History\\History.IE5\\index\.dat$", re.I),
            re.compile(r".*\\Cookies\\.*", re.I),
            re.compile(r".*\\Temporary Internet Files\\Content.IE5\\index\.dat$", re.I),
            re.compile(r".*\\Microsoft\\Edge\\User Data\\Default\\.*", re.I),
            # Google Chrome
            re.compile(r".*\\Application\\User Data\\Google\\Chrome\\.*", re.I),
            re.compile(r".*\\Local\\Google\\Chrome\\User Data\\Default\\.*", re.I),
            re.compile(r".*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\.*", re.I),
            # Chromium-based Browsers
            re.compile(r".*\\Application\\User Data\\Chromium\\.*", re.I),
            re.compile(r".*\\AppData\\Local\\Chromium\\.*", re.I),
            re.compile(r".*\\Application\\User Data\\ChromePlus\\.*", re.I),
            re.compile(r".*\\AppData\\Local\\MapleStudio\\ChromePlus\\.*", re.I),
            re.compile(r".*\\Application\\User Data\\Nichrome\\.*", re.I),
            re.compile(r".*\\AppData\\Local\\Nichrome\\User Data\\Default\\.*", re.I),
            re.compile(r".*\\Application\\User Data\\Bromium\\.*", re.I),
            re.compile(r".*\\AppData\\Local\\Bromium\\User Data\\Default\\.*", re.I),
            re.compile(r".*\\Application\\User Data\\RockMelt\\.*", re.I),
            re.compile(r".*\\AppData\\Local\\RockMelt\\User Data\\Default\\.*", re.I),
            re.compile(r".*\\Application\\User Data\\Flock\\.*", re.I),
            re.compile(r".*\\AppData\\Local\\Flock\\.*", re.I),
            re.compile(r".*\\Application\\User Data\\Comodo\\Dragon\\.*", re.I),
            re.compile(r".*\\AppData\\Local\\Comodo\\Dragon\\.*", re.I),
            re.compile(r".*\\BraveSoftware\\Brave-Browser\\User Data\\Default\\.*", re.I),
            # Opera
            re.compile(r".*\\Application\\User Data\\Opera\\.*", re.I),
            re.compile(r".*\\AppData\\Roaming\\Opera\\Opera\\.*", re.I),
            re.compile(r".*\\AppData\\Roaming\\Opera Software\\Opera Stable\\.*", re.I),
            # Safari
            re.compile(r".*\\Apple Computer\\Safari\\WebpageIcons\.db$", re.I),
            re.compile(r".*\\Apple Computer\\Safari\\History\.db$", re.I),
            re.compile(r".*\\Apple Computer\\Safari\\LastSession\.plist$", re.I),
            # Others
            re.compile(r".*\\AppData\\Local\\Spark\\User Data\\Default\\.*", re.I),
            re.compile(r".*\\AppData\\Local\\Nichrome\\User Data\\Default\\.*", re.I),
            re.compile(r".*\\AppData\\Local\\Titan Browser\\User Data\\Default\\.*", re.I),
            re.compile(r".*\\AppData\\Local\\Rockmelt\\User Data\\Default\\.*", re.I),
            re.compile(r".*\\AppData\\Local\\Torch\\User Data\\Default\\.*", re.I),
            re.compile(r".*\\AppData\\Local\\.*\\YandexBrowser\\User Data\\Default\\.*", re.I),
        ]

    def on_call(self, call, process):
        # If the current process appears to be a browser, continue.
        # TODO: implement better checks here -- the malware can be named whatever it wants or can
        # inject into browser processes
        if process["process_name"].lower() in ("iexplore.exe", "firefox.exe", "chrome.exe"):
            return None

        filename = None
        if call["api"] == "NtReadFile":
            filename = self.get_argument(call, "HandleName")
        elif call["api"] == "NtQueryAttributesFile":
            filename = self.get_argument(call, "FileName")
        else:
            filename = self.get_argument(call, "ExistingFileName")
        if not filename:
            return None

        for indicator in self.indicators:
            if indicator.match(filename):
                self.filematches.add(filename)
                if self.pid:
                    self.mark_call()
                self.saw_stealer = True
                self.artifacts_counter += 1

    def on_complete(self):
        if self.artifacts_counter >= self.MALICIOUS_ARTIFACTS_THRESHOLD:
            for file in self.filematches:
                self.data.append({"file": file})
            return self.saw_stealer
        return False
