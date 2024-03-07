# Copyright (C) 2012,2014 Claudio "nex" Guarnieri (@botherder), Optiv, Inc. (brad.spengler@optiv.com)
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


class DiskInformation(Signature):
    name = "antivm_generic_disk"
    description = "Queries information on disks, possibly for anti-virtualization"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex", "Optiv"]
    minimum = "1.2"
    evented = True
    ttps = ["T1082", "T1106", "T1497"]  # MITRE v6,7,8
    ttps += ["T1497.001"]  # MITRE v7,8
    ttps += ["U1312", "U1332"]  # Unprotect
    mbcs = ["OB0001", "B0009", "B0009.015", "OB0007", "E1082"]

    filter_apinames = set(
        ["NtCreateFile", "NtOpenFile", "NtClose", "DeviceIoControl", "NtDuplicateObject", "NtDeviceIoControlFile"]
    )

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = 0
        self.handles = dict()
        self.office_proc_list = [
            "wordview.exe",
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
            "acrord32.exe",
            "acrord64.exe",
            "acrobat.exe",
        ]

    def on_call(self, call, process):
        if process["process_name"].lower() in self.office_proc_list:
            return False

        ioctls = [
            0x2D1400,  # IOCTL_STORAGE_QUERY_PROPERTY
            0x70000,  # IOCTL_DISK_GET_DRIVE_GEOMETRY
            0x700A0,  # IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
            0x4D008,  # IOCTL_SCSI_MINIPORT
            0x7405C,  # IOCTL_DISK_GET_LENGTH_INFO
        ]

        if process is not self.lastprocess:
            self.handles = dict()
            self.lastprocess = process

        if call["api"] == "NtDuplicateObject" and call["status"]:
            tgtarg = self.get_argument(call, "TargetHandle")
            if tgtarg:
                srchandle = int(self.get_argument(call, "SourceHandle"), 16)
                tgthandle = int(tgtarg, 16)
                if srchandle in self.handles:
                    self.handles[tgthandle] = self.handles[srchandle]
        elif call["api"] == "NtClose":
            handle = int(self.get_argument(call, "Handle"), 16)
            self.handles.pop(handle, None)
        elif (call["api"] == "NtCreateFile" or call["api"] == "NtOpenFile") and call["status"]:
            filename = self.get_argument(call, "FileName")
            handle = int(self.get_argument(call, "FileHandle"), 16)
            if filename and (
                filename.lower() == "\\??\\physicaldrive0"
                or filename.lower().startswith("\\device\\harddisk")
                or "scsi0" in filename.lower()
            ):
                if handle not in self.handles:
                    self.handles[handle] = filename
        elif call["api"] == "DeviceIoControl" or call["api"] == "NtDeviceIoControlFile":
            ioctl = int(self.get_argument(call, "IoControlCode"), 16)
            if call["api"] == "DeviceIoControl":
                handle = int(self.get_argument(call, "DeviceHandle"), 16)
            else:
                handle = int(self.get_argument(call, "FileHandle"), 16)
            if handle in self.handles and ioctl in ioctls:
                if self.pid:
                    self.mark_call()
                return True
