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


class FlareCAPADataManipulation(Signature):
    name = "flare_capa_datamanipulation"
    description = "CAPA detected data manipulation (encryption, encoding, hashing)"
    severity = 1
    categories = ["compiler"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1132"]
    confidence = 50

    def run(self):
        ret = False

        target = self.results.get("target", {})
        if target.get("category") in ("file", "static") and target.get("file"):
            capa = self.results["target"]["file"].get("flare_capa", [])
            if capa:
                samplesha256 = capa["sha256"]
                capabilities = capa["CAPABILITY"]
                for namespace, capability in capabilities.items():
                    if "data-manipulation" in namespace:
                        ret = True
                        joined = ", ".join(capability)
                        self.data.append({"target": "SHA256 %s - %s %s" % (samplesha256, namespace, joined)})

        for block in self.results.get("CAPE", {}).get("payloads", []) or []:
            capa = block.get("flare_capa", [])
            if capa:
                samplesha256 = capa["sha256"]
                capabilities = capa["CAPABILITY"]
                for namespace, capability in capabilities.items():
                    if "data-manipulation" in namespace:
                        ret = True
                        joined = ", ".join(capability)
                        self.data.append({"payload": "SHA256 %s - %s %s" % (samplesha256, namespace, joined)})

        for keyword in ("procdump", "procmemory", "extracted", "dropped"):
            if self.results.get(keyword) is not None:
                for block in self.results.get(keyword, []):
                    if not isinstance(block, dict):
                        continue
                    capa = block.get("flare_capa", [])
                    if capa:
                        samplesha256 = capa["sha256"]
                        capabilities = capa["CAPABILITY"]
                        for namespace, capability in capabilities.items():
                            if "data-manipulation" in namespace:
                                ret = True
                                joined = ", ".join(capability)
                                self.data.append({keyword: "SHA256 %s - %s %s" % (samplesha256, namespace, joined)})

        return ret
