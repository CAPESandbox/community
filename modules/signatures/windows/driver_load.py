# Copyright (C) 2015 Optiv Inc. (brad.spengler@optiv.com)
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

class DriverLoad(Signature):
    name = "driver_load"
    description = "Loads a driver"
    severity = 2
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True
    ttps = ["T1215"]  # MITRE v6
    ttps += ["T1547", "T1547.006"]  # MITRE v7,8
    mbcs = ["OB0012", "F0010"]
    mbcs += ["OC0007", "C0023"]  # micro-behaviour

    filter_apinames = set(["NtLoadDriver"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.found_driverload = False

    def on_call(self, call, process):
        drivername = self.get_argument(call, "DriverServiceName")
        self.data.append({"driver_service_name": drivername})
        self.found_driverload = True
        if self.pid:
            self.mark_call()

    def on_complete(self):
        return self.found_driverload

class InstallKernelDriverService(Signature):
    name = "install_kernel_driver_service"
    description = "Installs a new kernel driver service, indicative of Bring Your Own Vulnerable Driver (BYOVD) attacks or a rootkit"
    severity = 3
    confidence = 80
    categories = ["driver", "rootkit", "bypass", "wiper"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    enabled = True
    ttps = ["T1543.003", "T1068", "T1547.006"]
    mbcs = ["E1543.003", "F0011"]

    filter_apinames = set(["CreateServiceA", "CreateServiceW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.found = False

    def on_call(self, call, process):
        service_type = self.get_argument(call, "ServiceType")
        binary_path = self.get_argument(call, "BinaryPathName")

        is_kernel_driver = (isinstance(service_type, str) and "SERVICE_KERNEL_DRIVER" in service_type) or \
                           service_type in (1, "1", "0x00000001")

        if is_kernel_driver and binary_path and binary_path.lower().endswith(".sys"):
            self.found = True
            self.mark_call()
                
    def on_complete(self):
        return self.found
