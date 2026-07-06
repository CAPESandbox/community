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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature


class FileOwnershipTakeover(Signature):
    name = "file_ownership_takeover"
    description = "Attempts to take ownership of files or directories using system utilities, indicative of ransomware/wipers staging access to protected files before destruction or for information theft"
    severity = 2
    confidence = 60
    categories = ["ransomware", "wiper", "impact", "infostealer"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1222.001"]
    mbcs = ["OB0006", "E1222"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

        # takeown.exe argument patterns that indicate bulk ownership changes.
        # /r = recursive traversal. /f <path> = target file or directory.
        # A single non-recursive takeown on one file can be a legitimate admin
        # action; recursive or system-path-targeting is the indicator.
        self.takeown_bulk_flags = [
            "/r",
            "/f *",
        ]

        # icacls.exe: /setowner changes the owner. /t = traverse subdirectories,
        # /c = continue on error. Either recursive flag makes it bulk.
        self.icacls_owner_flags = [
            "/setowner",
        ]
        self.icacls_recursive_flags = [
            "/t",
            "/r",
        ]

        # PowerShell ownership methods
        self.ps_ownership_patterns = [
            "set-acl",
            "setaccesscontrol",
            "setowner",
            "takeownership",
            "system.security.accesscontrol",
            "identityreference",
        ]

        # secedit can be used to apply security templates that change ownership
        self.secedit_patterns = [
            "secedit",
        ]

        # High-value target paths that escalate severity when targeted
        self.high_value_paths = [
            "\\windows\\system32",
            "\\windows\\syswow64",
            "\\windows\\system",
            "c:\\windows",
            "\\program files",
            "\\program files (x86)",
        ]

    def run(self):
        ret = False
        commands = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])

        for cmdline in commands:
            lower = cmdline.lower()

            # takeown.exe
            if "takeown" in lower:
                is_bulk = any(f in lower for f in self.takeown_bulk_flags)
                is_high_value = any(p in lower.replace("/", "\\") for p in self.high_value_paths)
                if is_bulk or is_high_value:
                    self.data.append({"command": cmdline})
                    if is_high_value:
                        self.severity = 3
                    ret = True

            # icacls.exe /setowner
            elif "icacls" in lower and any(f in lower for f in self.icacls_owner_flags):
                is_recursive = any(f in lower for f in self.icacls_recursive_flags)
                self.data.append({"command": cmdline})
                if is_recursive or any(p in lower.replace("/", "\\") for p in self.high_value_paths):
                    self.severity = 3
                ret = True

            # PowerShell ownership
            elif "powershell" in lower or "pwsh" in lower:
                if any(p in lower for p in self.ps_ownership_patterns):
                    self.data.append({"command": cmdline})
                    if any(p in lower.replace("/", "\\") for p in self.high_value_paths):
                        self.severity = 3
                    ret = True

            # secedit /configure applying a security template
            elif "secedit" in lower and any(f in lower for f in ["/configure", "-configure"]):
                self.data.append({"command": cmdline})
                ret = True

        return ret


class TakeOwnershipCheck(Signature):
    name = "takeownership_check"
    description = "Looks up SeTakeOwnershipPrivilege repeatedly, likely taking file ownership restrictions as preparation for ransomware/wiper destruction or information theft"
    severity = 2
    confidence = 60
    categories = ["wiper", "impact", "ransomware", "infostealer"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1222.001", "T1485"]
    mbcs = ["OB0010", "E1222"]

    filter_apinames = set(["LookupPrivilegeValueW", "LookupPrivilegeValueA"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.threshold = 5
        self.count = 0

    def on_call(self, call, process):
        if not call["status"]:
            return None
        priv = (self.get_argument(call, "PrivilegeName") or self.get_argument(call, "Name") or "").lower()
        if priv in ("setakeownershipprivilege", "se take ownership privilege"):
            self.count += 1
            if self.count == self.threshold:
                self.mark_call()

    def on_complete(self):
        if self.count >= self.threshold:
            self.data.append({"privilege_lookup_count": self.count, "privilege": "SeTakeOwnershipPrivilege"})
            return True
        return False


class PerFileAclTokenCheck(Signature):
    name = "per_file_acl_token_check"
    description = "Performs high-volume NtQueryInformationToken calls for TokenUser and TokenGroups, indicative of wiper/ransomware checking whether it has write permission to each file"
    severity = 2
    confidence = 50
    categories = ["wiper", "ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1485", "T1069"]
    mbcs = ["OB0010", "E1485"]

    filter_apinames = set(["NtQueryInformationToken"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.watched_classes = {"5", "6"}
        self.threshold = 100
        self.count = 0

    def on_call(self, call, process):
        if not call["status"]:
            return None
        cls = self.get_argument(call, "TokenInformationClass") or ""
        if cls in self.watched_classes:
            self.count += 1
            if self.count == self.threshold:
                self.mark_call()

    def on_complete(self):
        if self.count >= self.threshold:
            self.data.append({"token_query_count": self.count, "indicates": "per-file permission evaluation on large file set"})
            return True
        return False
