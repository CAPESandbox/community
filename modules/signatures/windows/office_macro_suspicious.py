# Copyright (C) 2018 Kevin Ross
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


class OfficeMacroSuspicious(Signature):
    name = "office_macro_suspicious"
    description = "The Office file contains a macro with suspicious strings"
    severity = 3
    categories = ["office"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1064"]  # MITRE v6
    ttps += ["T1059"]  # MITRE v6,7,8
    ttps += ["T1059.005"]  # MITRE v7,8

    def run(self):
        ret = False
        strings = []
        if self.results.get("target", {}).get("category", "") not in ("url", "pcap"):
            if (
                self.results.get("target", {})
                .get("file", {})
                .get("office", {})
                .get("Macro", {})
                .get("Analysis", {})
                .get("Suspicious")
            ):
                for string, description in self.results.get("target", {})["file"]["office"]["Macro"]["Analysis"]["Suspicious"]:
                    if string not in strings:
                        strings.append(string)
                        self.data.append({string: description})
                ret = True

        return ret


class OfficeMacroIOC(Signature):
    name = "office_macro_ioc"
    description = "The Office file contains a macro with potential indicators of compromise"
    severity = 3
    categories = ["office"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1064"]  # MITRE v6
    ttps += ["T1059"]  # MITRE v6,7,8
    ttps += ["T1059.005"]  # MITRE v7,8

    def run(self):
        ret = False
        if self.results.get("target", {}).get("category", "") not in ("url", "pcap"):
            if self.results.get("target", {}).get("file", {}).get("office", {}).get("Macro", {}).get("Analysis", {}).get("IOCs"):
                for description, indicator in self.results.get("target", {})["file"]["office"]["Macro"]["Analysis"]["IOCs"]:
                    for description, indicator in self.results["target"]["office"]["Macro"]["Analysis"]["IOCs"]:
                        self.data.append({description: indicator})
                    ret = True

        return ret


class OfficeMacroAutoExecution(Signature):
    name = "office_macro_autoexecution"
    description = "The Office file contains a macro with auto execution"
    severity = 2
    categories = ["office"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1064"]  # MITRE v6
    ttps += ["T1059"]  # MITRE v6,7,8
    ttps += ["T1059.005"]  # MITRE v7,8

    def run(self):
        ret = False
        strings = []
        if self.results.get("target", {}).get("category", "") not in ("url", "pcap"):
            if (
                self.results.get("target", {})
                .get("file", {})
                .get("office", {})
                .get("Macro", {})
                .get("Analysis", {})
                .get("AutoExec")
            ):
                for string, description in self.results.get("target", {})["file"]["office"]["Macro"]["Analysis"]["AutoExec"]:
                    if string not in strings:
                        strings.append(string)
                        self.data.append({string: description})
                ret = True

        return ret


class OfficeMacroMaliciousPredition(Signature):
    name = "office_macro_malicious_prediction"
    description = "A machine learning model classified an Office macro as malicious"
    severity = 3
    categories = ["office", "macro"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1064"]  # MITRE v6
    ttps += ["T1059"]  # MITRE v6,7,8
    ttps += ["T1059.005"]  # MITRE v7,8

    def run(self):
        ret = False
        if "mmbot" in self.results:
            if "prediction" in self.results["mmbot"]:
                prediction = self.results["mmbot"]["prediction"]
                confidence = self.results["mmbot"]["confidence"]
                if prediction == "malicious":
                    self.data.append({"mmbot": "prediction: %s confidence: %s" % (prediction, confidence)})
                    ret = True

        return ret
