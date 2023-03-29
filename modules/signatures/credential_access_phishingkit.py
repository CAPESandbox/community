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

class PhishingKit(Signature):
    name = "Phishing_kit_detected"
    description = "Phishing Kit Detected, sample is trying to harvest credentials"
    severity = 3
    confidence = 100
    weight = 3
    categories = ["credential_access","evasion","infostealer","phishing", "static"]
    families = ["PhishingKit"]
    authors = ["Yasin Tas",  "Eye Security"]
    enabled = True
    minimum = "1.2"
    ttps = ["T1111", "T1193", "T1140"]  # MITRE v6
    ttps += ["T1566.001"]  # MITRE v6,7,8
    ttps += ["T1606"]  # MITRE v7,8
    mbcs = ["C0029.003"]  # micro-behaviour

    evented = True

    def run(self):
        found_sig = False
        if "strings" in self.results:
            found_sig = True
            return found_sig 