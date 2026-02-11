# Copyright (C) 2026 Kevin Ross
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

class AntiVMWMI(Signature):
    name = "antivm_wmi"
    description = "Executes WMI queries that can be used for anti-virtualization"
    severity = 3
    confidence = 80
    categories = ["anti-vm"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    enabled = True
    ttps = ["T1497.001", "T1082", "T1047", "T1497"]
    mbcs = ["B0001.002", "B0007", "OB0001"]

    filter_apinames = set(["WMI_ExecQuery"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.filenames = [
            "acpi.sys", "hdaudbus.sys", "monitor.sys", "mssmbios.sys",
            "ndis.sys", "pci.sys", "portcls.sys", "processr.sys",
            "vboxguest.sys", "vboxmouse.sys", "vboxvideo.sys", 
            "vmmouse.sys", "vmtoolsd.exe", "vmumouse.sys", "vmvga.sys"
        ]
        self.wmiclasses = [
            "msacpi_thermalzonetemperature", "win32_baseboard", "win32_battery",
            "win32_bios", "win32_cachememory", "win32_computersystem",
            "win32_desktopmonitor", "win32_diskdrive", "win32_fan",
            "win32_networkadapter", "win32_physicalmedia", "win32_physicalmemory",
            "win32_pnpentity", "win32_processor", "win32_videocontroller"
        ]

    def on_call(self, call, process):
        if call["api"] == "WMI_ExecQuery":
            query = self.get_argument(call, "Query")
            if query:
                querylower = query.lower()
                for filename in self.filenames:
                    if filename in querylower:
                        self.ret = True
                        self.mark_call()
                for wmiclass in self.wmiclasses:
                    if wmiclass in querylower:
                        self.ret = True
                        self.mark_call()

    def on_complete(self):
        return self.ret
