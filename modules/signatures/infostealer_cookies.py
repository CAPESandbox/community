# Copyright (C) 2021 bartblaze
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


class CookiesStealer(Signature):
    name = "infostealer_cookies"
    description = "Harvests cookies for information gathering"
    severity = 3
    categories = ["infostealer"]
    authors = ["bartblaze"]
    minimum = "0.5"
    evented = True
    ttps = ["T1539"]  # MITRE v6,7,8

    filter_apinames = ["NtQueryValueKey"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.data = []
        self.indicators = [
            ".*\\\\Chromium\\\\User Data\\\\.*\\\\Cookies$",
            ".*\\\\Google\\\\Chrome\\\\User Data\\\\.*\\\\Cookies$",
            ".*\\\\Microsoft\\\\Windows\\\\INetCookies$",
            ".*\\\\Packages\\\\.*\\\\AC\\\\.*\\\\MicrosoftEdge\\\\Cookies$",
            ".*\\\\UCBrowser\\\\User Data_i18n\\\\.*\\\\Cookies.9$",
            ".*\\\\Yandex\\\\YandexBrowser\\\\User Data\\\\.*\\\\Cookies$",
            ".*\\\\Apple Computer\\\\Safari\\\\Cookies\\\\Cookies.binarycookies$",
            ".*\\\\Microsoft\\\\Windows\\\\Cookies$",
            ".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\cookies.sqlite$",
            ".*\\\\Opera Software\\\\Opera Stable\\\\Cookies$",
            ".*\\\\Brave-Browser\\\\User Data\\\\.*\\\\Cookies$",
        ]
        self.safe_indicators = ["chrome.exe", 
                                "firefox.exe",
                                "opera.exe", 
                                "msedge.exe", 
                                "acrobat.exe",
                                "excel.exe",
                                "winword.exe",
                                ]
    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname in self.safe_indicators:
            return False
        for indicator in self.indicators:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.add_match(process, 'api', match)
            #     self.data.append({"cookie": match})
            #     return True
    def on_complete(self):
        return self.has_matches()
