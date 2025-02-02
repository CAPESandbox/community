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


class AntiAnalysisTLSSection(Signature):
    name = "antianalysis_tls_section"
    description = "Contains .tls (Thread Local Storage) section"
    severity = 2
    categories = ["anti-analysis"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1055"]  # MITRE v6
    ttps += ["T1055"]  # MITRE v6,7,8
    ttps += ["T1055.005"]  # MITRE v7,8
    mbcs = ["B0002", "B0003", "E1055"]

    def run(self):
        ret = False

        target = self.results.get("target", {})
        if target.get("category") in ("file", "static") and target.get("file"):
            pe = self.results["target"]["file"].get("pe", [])
            if pe:
                for section in pe["sections"]:
                    if section["name"].lower().startswith(".tls"):
                        self.data.append({"section": section})
                        ret = True

        return ret
