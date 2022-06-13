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


class TampersETW(Signature):
    name = "tampers_etw"
    description = "Tampers with ETW"
    severity = 3
    categories = ["evasion", "tampering"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttps = ["T1054", "T1562"]

    def run(self):
        reg_indicators = [
            "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Microsoft\.NETFramework\\\\ETWEnabled",
            "HKEY_CURRENT_USER\\\\Environment\\\\COMPlus_ETWEnabled",
            "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\Environment\\\\COMPlus_ETWEnabled",
        ]

        cmd_indicators = [".*set\scomplus_etwenabled.*", ".*env:complus_etwenabled.*", ".*etwenabled.*(value|\/d)\s0.*"]

        for rindicator in reg_indicators:
            match = self.check_write_key(pattern=rindicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        for cindicator in cmd_indicators:
            match = self.check_executed_command(pattern=cindicator, regex=True)
            if match:
                self.data.append({"cmdline": match})
                return True

        return False
