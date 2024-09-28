# Copyright (C) 2020 ditekshen
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


class EchelonFiles(Signature):
    name = "echelon_files"
    description = "Echelon infostealer file artifacts detected"
    severity = 3
    categories = ["infostealer"]
    families = ["Echelon"]
    authors = ["ditekshen"]
    minimum = "2.0"
    evented = True
    ttps = ["T1503"]  # MITRE v6
    ttps += ["T1003", "T1115"]  # MITRE v6,7,8
    ttps += ["T1555", "T1555.003"]  # MITRE v7,8
    mbcs = ["OB0005", "OB0003"]
    mbcs += ["OC0001", "C0052"]  # micro-behaviour

    def run(self):
        score = 0
        fpath = r".*\\AppData\\Roaming\\.*\\"
        flist = (
            r"Processes\.txt",
            r"Computer\.txt",
            r"Clipboard\.txt",
            r"Screenshot\.jpeg",
            r"Browsers\\Cards\\Cards_Google\.txt",
            r"Browsers\\Cookies\\Cookies_Google\.txt",
            r"Browsers\\Passwords\\Passwords_Google\.txt",
            r"Browsers\\Autofills\\Autofills_Google\.txt",
            r"Browsers\\Downloads\\Downloads_Google\.txt",
            r"Browsers\\History\\History_Google\.txt",
            r"Browsers\\Passwords\\Passwords_Edge\.txt",
        )

        for lfile in flist:
            indicator = fpath + lfile
            match = self.check_write_file(pattern=indicator, regex=True)
            if match:
                score += 1
                self.data.append({"file": match})

        if score > 6:
            return True

        return False
