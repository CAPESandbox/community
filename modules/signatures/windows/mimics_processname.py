# Copyright (C) 2019 ditekshen
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


class MasqueradesProcessName(Signature):
    name = "masquerade_process_name"
    description = "Attempts to masquerade or mimic a legitimate process or file name"
    severity = 3
    categories = ["masquerading", "evasion", "execution"]
    authors = ["ditekshen"]
    minimum = "0.5"
    ttps = ["T1036"]  # MITRE v6,7,8
    evented = True

    def run(self):
        indicators = [
            r".*svhost\.(exe|dll)$",
            r".*svhhost\.(exe|dll)$",
            r".*svvhost\.(exe|dll)$",
            r".*srvhost\.(exe|dll)$",
            r".*swchost\.(exe|dll)$",
            r".*svvhost\.(exe|dll)$",
            r".*svchosts\.(exe|dll)$",
            r".*svch0st\.(exe|dll)$",
            r".*skhosts\.(exe|dll)$",
            r".*svhoost\.(exe|dll)$",
            r".*scvhost\.(exe|dll)$",
            r".*svschost\.(exe|dll)$",
            r".*svchostt\.(exe|dll)$",
            r".*spoolsrv\.(exe|dll)$",
            r".*spoolsvc\.(exe|dll)$",
            r".*spoolscv\.(exe|dll)$",
            r".*dllh0st\.(exe|dll)$",
            r".*taskh0st\.(exe|dll)$",
        ]

        for indicator in indicators:
            procmatch = self.check_process_name(pattern=indicator)
            if procmatch:
                self.data.append({"process": procmatch})
                self.ttps += ["T1036.004"]  # MITRE v7,8
                return True
            filematch = self.check_file(pattern=indicator, regex=True)
            if filematch:
                self.data.append({"file": filematch})
                self.ttps += ["T1036.005"]  # MITRE v7,8
                return True
            wfilematch = self.check_write_file(pattern=indicator, regex=True)
            if wfilematch:
                self.data.append({"file": wfilematch})
                self.ttps += ["T1036.005"]  # MITRE v7,8
                return True

        return False
