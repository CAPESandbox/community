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

class SystemInfoDiscoveryCMD(Signature):
    name = "system_info_disovery_cmd"
    description = "Collects system information via command line"
    severity = 2
    categories = ["discovery"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttp = ["T1082"]
    evented = True

    def on_complete(self):
        indicators = [
            "([A-Za-z]:\\\\Windows\\\\System32\\\\)?hostname(.exe)?.*",
            "([A-Za-z]:\\\\Windows\\\\System32\\\\)?systeminfo(.exe)?.*",
            "([A-Za-z]:\\\\Windows\\\\System32\\\\)?net(.exe)?\sconfig(Server|Workstation)",
        ]

        for indicator in indicators:
            match = self.check_executed_command(pattern=indicator, regex=True)
            if match:
                self.data.append({"command": match})
                return True

        return False

class SystemUserDisoveryCMD(Signature):
    name = "system_user_disovery_cmd"
    description = "Collects system owner/user information via command line"
    severity = 2
    categories = ["discovery"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttp = ["T1033"]
    evented = True

    def on_complete(self):
        indicators = [
            "([A-Za-z]:\\\\Windows\\\\System32\\\\)?whoami(.exe)?.*",
        ]

        for indicator in indicators:
            match = self.check_executed_command(pattern=indicator, regex=True)
            if match:
                self.data.append({"command": match})
                return True

        return False

class SystemAccountDisoveryCMD(Signature):
    name = "system_account_disovery_cmd"
    description = "Collects system account information via command line"
    severity = 2
    categories = ["discovery"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttp = ["T1087"]
    evented = True

    def on_complete(self):
        indicators = [
            ".*net\s(user|group|localgroup).*",
        ]

        for indicator in indicators:
            match = self.check_executed_command(pattern=indicator, regex=True)
            if match:
                self.data.append({"command": match})
                return True

        return False

class SystemNetworkDiscoveryCMD(Signature):
    name = "system_network_discovery_cmd"
    description = "Collects system network information via command line"
    severity = 3
    categories = ["discovery"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttp = ["T1016", "S0103", "S0359"]
    evented = True

    def on_complete(self):
        indicators = [
            "([A-Za-z]:\\\\Windows\\\\System32\\\\)?route(.exe)?.*",
            ".*netsh(\")?\swlan\sshow\s(profile|networks).*",
            "([A-Za-z]:\\\\Windows\\\\System32\\\\)?ipconfig(.exe)?.*",
            "([A-Za-z]:\\\\Windows\\\\System32\\\\)?nltest(.exe)?.*",
            ".*net\sview.*",
        ]

        for indicator in indicators:
            match = self.check_executed_command(pattern=indicator, regex=True)
            if match:
                self.data.append({"command": match})
                return True

        return False

class SystemInfoDiscoveryPWSH(Signature):
    name = "system_info_disovery_pwsh"
    description = "Collects system information via PowerShell"
    severity = 2
    categories = ["discovery"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttp = ["T1082"]
    evented = True

    def on_complete(self):
        indicators = [
            ".*Get-Host.*",
            ".*Get-ComputerInfo.*",
            ".*Get-WmiObject.*Win32_Computersystem.*",
        ]

        for indicator in indicators:
            match = self.check_executed_command(pattern=indicator, regex=True)
            if match:
                self.data.append({"command": match})
                return True

        return False

class SystemNetworkDiscoveryPWSH(Signature):
    name = "system_network_discovery_pwsh"
    description = "Collects system network information via PowerShell"
    severity = 3
    categories = ["discovery"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttp = ["T1016"]
    evented = True

    def on_complete(self):
        indicators = [
            ".*Get-NetIPConfiguration.*",
            ".*Get-NetIPAddress.*",
        ]

        for indicator in indicators:
            match = self.check_executed_command(pattern=indicator, regex=True)
            if match:
                self.data.append({"command": match})
                return True

        return False       