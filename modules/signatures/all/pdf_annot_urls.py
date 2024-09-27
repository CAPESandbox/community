# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
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


class PDF_Annot_URLs_Checker(Signature):
    name = "pdf_annot_urls_checker"
    description = "The PDF contains a Link Annotation"
    severity = 2  # Default severity
    categories = ["static"]
    authors = ["Wassime BATTA"]
    minimum = "0.5"

    filter_analysistypes = set(["file", "static"])

    malicious_tlds_file = "/opt/CAPEv2/data/malicioustlds.txt"

    def __init__(self, *args, **kwargs):
        super(PDF_Annot_URLs_Checker, self).__init__(*args, **kwargs)
        self.malicious_tlds = self.load_malicious_tlds()

    def load_malicious_tlds(self):
        malicious_tlds = set()
        with open(self.malicious_tlds_file, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("."):
                    malicious_tlds.add(line)
        return malicious_tlds

    def run(self):
        found_malicious_extension = False
        found_malicious_domain = False
        found_domain_only = False
        suspect = False

        if "PDF" in self.results["target"]["file"].get("type", ""):
            if "Annot_URLs" in self.results["target"]["file"]["pdf"]:
                for entry in self.results["target"]["file"]["pdf"]["Annot_URLs"]:
                    entry_lower = entry.lower()
                    self.data.append({"url": entry})
                    if entry_lower.endswith(
                        (".exe", ".php", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1", ".sh")
                    ) and not entry_lower.startswith("mailto:"):
                        found_malicious_extension = True

                    if entry_lower.startswith("http://") or entry_lower.startswith("https://"):
                        domain_start = entry_lower.find("//") + 2
                        domain_end = entry_lower.find("/", domain_start)
                        if domain_end == -1:
                            domain = entry_lower[domain_start:]
                        else:
                            domain = entry_lower[domain_start:domain_end]

                        for malicious_tld in self.malicious_tlds:
                            if domain.endswith(malicious_tld):
                                found_malicious_domain = True
                                break
                        else:
                            # If no malicious TLDs detected, set found_domain_only to True
                            found_domain_only = True

            if found_malicious_domain or found_malicious_extension:
                self.severity = 6
                self.description = "The PDF contains a Malicious Link Annotation"
                suspect = True
            elif found_domain_only:
                self.severity = 2
                self.description = "The PDF contains a Link Annotation"
                suspect = True

        return suspect
