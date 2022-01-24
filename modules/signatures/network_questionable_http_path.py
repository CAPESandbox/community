# Copyright (C) 2021 Quadrant Information Security, written by Zane C. Bowers-Hadley
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

# This is for hitting on HTTP/HTTPS fetches out to hosts that have
# likely been compromised.

# common_dirs contains a lists of directorys that are commonly given
# 777 perms and get drek written to them. Or with out 777 written to
# via the a compromised PHP script or the like.

from lib.cuckoo.common.abstracts import Signature

# common dir names to check for the usage of
common_dirs=[
            "/wp-content/",
            "/template/",
            "/tmp/",
            "/temp/",
            "/data/",
             ]
# executable or archive files to checked for being pulled down
common_types=[
            ".zip",
            ".exe",
            ".com",
            ".bz2",
            ".gz",
            ".bz",
            ".ace",
            ".tar",
            ".tgz",
            ".tbz",
            ]

class NetworkQuestionableHttpPath(Signature):
    name = "network_questionable_http_path"
    description = "Makes a suspicious HTTP request to a commonly exploitable directory with questionable file ext"
    severity = 3
    confidence = 100
    categories = ["network"]
    authors = ["Zane C. Bowers-Hadley"]
    minimum = "1.3"

    filter_analysistypes = set(["file"])

    def run(self):
        if "network" in self.results and "http" in self.results["network"]:
            for host in self.results["network"]["http"]:
                path = host["path"]
                lc_path = path.lower()
                for common_dir in common_dirs:
                    found_location = lc_path.find(common_dir)
                    if found_location != -1:
                        for common_type in common_types:
                            if lc_path.find(common_type, found_location) != -1:
                                self.data.append({'uri' : host["uri"]})
        if self.data:
            return True
        else:
            return False

class NetworkQuestionableHttpsPath(Signature):
    name = "network_questionable_https_path"
    description = "Makes a suspicious HTTPS request to a commonly exploitable directory with questionable file ext"
    severity = 3
    confidence = 100
    categories = ["network"]
    authors = ["Zane C. Bowers-Hadley"]
    minimum = "1.3"

    filter_analysistypes = set(["file"])

    def run(self):
        if "network" in self.results and "https" in self.results["network"]:
            for host in self.results["network"]["https"]:
                path = host["path"]
                lc_path = path.lower()
                for common_dir in common_dirs:
                    found_location = lc_path.find(common_dir)
                    if found_location != -1:
                        for common_type in common_types:
                            if lc_path.find(common_type, found_location) != -1:
                                self.data.append({'uri' : host["uri"]})
        if self.data:
            return True
        else:
            return False
