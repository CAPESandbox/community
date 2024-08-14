# Copyright (C) 2015 KillerInstinct
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


class Procmem_Yara(Signature):
    name = "procmem_yara"
    description = "Yara detections observed in process dumps, payloads or dropped files"
    severity = 3
    categories = ["malware"]
    authors = ["KillerInstinct"]
    minimum = "0.5"

    def run(self):
        hits = []
        # Define Yara rule names here and categorize appropriately
        suspicious = []
        malicious = [
            "dyrecfgserverlist",
            "dyrecfginjectslist",
            "dyrecfgredirectlist",
            "dridexcfgbotid",
            "dridexcfgnodelist",
            "dridexcfgkeylog",
            "kazybot_rat",
            "darkcometconfig",
        ]

        for keyword in ("procdump", "procmemory", "extracted", "dropped"):
            if keyword in self.results and self.results[keyword] is not None:
                for process in self.results.get(keyword, []):
                    pid = process.get("pid", 0)
                    for sub_keyword in ("yara", "cape_yara"):
                        for rule in process.get(sub_keyword, []):
                            if (pid, rule["name"]) not in hits:
                                hits.append((pid, rule["name"], rule["strings"], rule["meta"].get("private")))

        for process in self.results.get("CAPE", {}).get("payloads", []) or []:
            pid = process.get("pid", 0)
            for sub_keyword in ("yara", "cape_yara"):
                for rule in process.get(sub_keyword, []):
                    if (pid, rule["name"]) not in hits:
                        hits.append((pid, rule["name"], rule["strings"], rule["meta"].get("private")))

        if hits:
            for pid, rule, data, private in hits:
                if rule.lower() in suspicious and self.severity == 3:
                    self.severity = 4
                elif rule.lower() in malicious and self.severity <= 4:
                    self.severity = 5
                if private:
                    self.data.append({"Hit": "PID %s triggered the Yara rule '%s'" % (pid, rule)})
                else:
                    self.data.append({"Hit": "PID %s triggered the Yara rule '%s' with data '%s'" % (pid, rule, data)})
            return True

        return False
