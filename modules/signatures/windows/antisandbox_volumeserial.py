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


class HardwareIdProfiling(Signature):
    name = "hardware_id_profiling"
    description = "Queries the Volume Serial Number or Physical Hardware ID, possibly for anti-sandbox, victim profiling or environmental keying"
    severity = 3
    confidence = 80
    categories = ["evasion", "recon", "anti-sandbox"]
    authors = ["Kevin Ross", "Gemini"]
    minimum = "1.3"
    evented = True
    ttps = ["T1082", "T1480"]
    mbcs = ["E1082", "E1480.001"]

    filter_apinames = {
        "GetVolumeInformationW",
        "GetVolumeInformationA",
        "GetVolumeInformationByHandleW",
        "DeviceIoControl",
        "NtDeviceIoControlFile",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

    def on_call(self, call, process):
        api = call["api"]
        if api in ("GetVolumeInformationW", "GetVolumeInformationA", "GetVolumeInformationByHandleW"):
            self.mark_call()
            self.ret = True

        elif api in ("DeviceIoControl", "NtDeviceIoControlFile"):
            code = self.get_argument(call, "IoControlCode") or self.get_argument(call, "dwIoControlCode")

            if code:
                try:
                    code_val = int(code, 16) if isinstance(code, str) and str(code).startswith("0x") else int(code)

                    # 0x2D1400 = IOCTL_STORAGE_QUERY_PROPERTY (Retrieves the true hardware serial number)
                    # 0x070000 = IOCTL_DISK_GET_DRIVE_GEOMETRY (Often used to check if running in a VM)
                    if code_val == 0x2D1400:
                        self.mark_call()
                        self.ret = True
                    elif code_val == 0x070000:
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        return self.ret
