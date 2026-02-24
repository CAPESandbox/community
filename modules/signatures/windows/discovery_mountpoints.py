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

class DiscoverRegistryMountPoints(Signature):
    name = "discover_registry_mount_points"
    description = "Queries registry mount points to identify historical or connected removable/network drives"
    severity = 2
    categories = ["discovery", "ransomware", "wiper"]
    authors = ["Kevin Ross"]
    ttps = ["T1082", "T1120"]

    def run(self):
        found_mounts = set()
        
        # We look for the CPC\Volume subkeys which contain the specific hardware IDs
        # The regex captures the GUIDs usually found in MountPoints2
        pattern = r".*\\Explorer\\MountPoints2\\CPC\\Volume\\\{[a-fA-F0-9-]+\}"
        
        matches = self.check_key(pattern=pattern, regex=True, all=True)
        
        if matches:
            for match in matches:
                # Normalize to prevent duplicates in the report
                match_upper = match.upper()
                if match_upper not in found_mounts:
                    found_mounts.add(match_upper)
                    self.data.append({"mount_point_key": match})

        if found_mounts:
            return True

        return False

class MountPointsVolumeDiscovery(Signature):
    name = "mountpoints_volume_discovery"
    description = "Queries the mount points and then resolves volume paths to enumerate storage devices"
    severity = 3
    confidence = 80
    categories = ["discovery", "ransomware", "wiper"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    enabled = True
    ttps = ["T1082", "T1120"] 

    filter_apinames = set([
        "NtOpenKey", "NtOpenKeyEx", "RegOpenKeyExW", "RegOpenKeyExA",
        "GetVolumeNameForVolumeMountPointW", "GetVolumeNameForVolumeMountPointA"
    ])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.accessed_mountpoints = False
        self.resolved_volumes = 0

    def on_call(self, call, process):
        api = call["api"]

        # Step 1: Detect access to the MountPoints2 Volume cache
        if api in ("NtOpenKey", "NtOpenKeyEx", "RegOpenKeyExW", "RegOpenKeyExA"):
            obj_name = self.get_argument(call, "ObjectAttributesName") or self.get_argument(call, "SubKey")
            if obj_name and "MountPoints2\\CPC\\Volume" in obj_name:
                self.accessed_mountpoints = True
                self.mark_call()

        # Step 2: Detect the translation of those volumes into usable paths
        elif api in ("GetVolumeNameForVolumeMountPointW", "GetVolumeNameForVolumeMountPointA"):
            if self.accessed_mountpoints:
                self.mark_call()
                self.resolved_volumes += 1
                
                # If it resolves multiple volumes after querying the registry, it's looping/enumerating
                if self.resolved_volumes >= 2:
                    self.ret = True

    def on_complete(self):
        return self.ret
