# Copyright (C) 2024 Kevin Ross
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


class QueriesKeyboardLayout(Signature):
    name = "queries_keyboard_layout"
    description = "Queries the keyboard layout"
    severity = 1
    categories = ["location_discovery"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1614"]  # MITRE v6,7,8

    filter_apinames = set(["GetKeyboardLayout"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

    def on_call(self, call, process):
        self.mark_call()
        self.ret = True

    def on_complete(self):
        return self.ret


class LanguageCheckReg(Signature):
    name = "language_check_registry"
    description = "Checks system language via registry key (possible geofencing)"
    severity = 1
    categories = ["location_discovery", "geofence"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1614", "T1627"]  # MITRE v6,7,8

    def run(self):
        ret = False
        indicators = [
            r".*\\SYSTEM\\ControlSet001\\Control\\Nls\\CustomLocale\\.*",
            r".*\\SYSTEM\\ControlSet001\\Control\\Nls\\ExtendedLocale\\.*",
        ]
        for indicator in indicators:
            match = self.check_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                ret = True

        return ret


class QueriesLocaleAPI(Signature):
    name = "queries_locale_api"
    description = "Queries the computer locale (possible geofencing)"
    severity = 1
    categories = ["location_discovery", "geofence"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1614", "T1627"]  # MITRE v6,7,8

    filter_apinames = set(["GetUserDefaultLCID", "GetUserDefaultLocaleName"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

    def on_call(self, call, process):
        self.mark_call()
        self.ret = True

    def on_complete(self):
        return self.ret
