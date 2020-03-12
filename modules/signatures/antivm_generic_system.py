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

class AntiVMSystem(Signature):
    name = "antivm_generic_system"
    description = "Checks the system manufacturer, likely for anti-virtualization"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttp = ["T1057", "T1012"]

    def run(self):
        if self.check_read_key(pattern= ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Control\\\\SystemInformation\\\\SystemManufacturer$", regex=True):
            return True

        return False