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


class VBoxDetectProvname(Signature):
    name = "antivm_vbox_provname"
    description = "Detects VirtualBox using WNetGetProviderName trick"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Optiv"]
    minimum = "1.3"
    evented = True
    ttps = ["T1016", "T1497"]  # MITRE v6,7,8
    ttps += ["T1497.001"]  # MITRE v7,8
    ttps += ["U1332"]  # Unprotect
    mbcs = ["OB0001", "B0009", "B0009.001"]

    filter_apinames = set(["WNetGetProviderNameW"])

    def on_call(self, call, process):
        nettype = int(self.get_argument(call, "NetType"))
        if nettype == 0x250000:
            if self.pid:
                self.mark_call()
            return True
