# Copyright (C) 2016 Kevin Ross
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

try:
    import re2 as re
except ImportError:
    import re


class RansomwareFileModifications(Signature):
    name = "ransomware_file_modifications"
    description = "Exhibits possible ransomware or wiper file modification behavior"
    severity = 3
    confidence = 50
    categories = ["ransomware", "wiper"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1486"]  # MITRE v6,7,8
    mbcs = ["OB0008", "E1486"]

    filter_apinames = set(
        ["MoveFileWithProgressW", "MoveFileWithProgressTransactedW", "NtCreateFile", "NtWriteFile", "NtSetInformationFile"]
    )

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.movefilecount = 0
        self.appendcount = 0
        self.appendemailcount = 0
        self.modifiedexistingcount = 0
        self.newextensions = []
        self.handles_by_pid = {}
        self._overwritten_files = set()
        self._behaviour_tags = []
        self.dispositiondeletecount = 0
        self._disposition_deleted = set()
        self.noise_paths = [
            "\\appdata\\local\\microsoft\\windows\\explorer\\iconcache_",
            "\\appdata\\local\\microsoft\\windows\\explorer\\iconcachetodelete\\",
            "\\inetcache",
            "\\temporary internet files",
            "\\cache",
            "\\temp\\",
            "\\windows\\",
            "\\program files\\",
            "\\program files (x86)\\",
            "\\programdata\\microsoft\\",
        ]
        self.handle_noise_paths = [
            "\\device\\",
            "\\pipe\\",
            "\\??\\pipe",
            "\\windows\\",
            "\\program files\\",
            "\\program files (x86)\\",
            "\\programdata\\microsoft\\",
            "\\systemroot\\",
        ]

    def _is_noise_path(self, path, table=None):
        if table is None:
            table = self.noise_paths
        pl = path.lower()
        return any(fragment in pl for fragment in table)

    def _append_tag(self, tag, mbcs_extra=None):
        if tag not in self._behaviour_tags:
            self._behaviour_tags.append(tag)
            if mbcs_extra:
                self.mbcs += mbcs_extra

    def _handle_rename(self, origfile, newfile):
        if not origfile or not newfile:
            return
        if self._is_noise_path(origfile) or self._is_noise_path(newfile):
            return

        self.movefilecount += 1

        if origfile.lower() == newfile.lower():
            return

        if "@" in newfile:
            self.appendemailcount += 1
            if self.pid and self.appendemailcount <= 10:
                self.mark_call()
            return

        orig_basename = origfile.rsplit("\\\\", 1)[-1].lower()
        new_basename = newfile.rsplit("\\\\", 1)[-1].lower()
        orig_base_no_ext = orig_basename.rsplit(".", 1)[0] or orig_basename
        if not new_basename.startswith(orig_base_no_ext):
            return

        origextextract = re.search(r"(\\.[a-zA-Z0-9_\\-]{1,})$", orig_basename)
        newextextract = re.search(r"(\\.[a-zA-Z0-9_\\-]{1,})$", new_basename)
        if not origextextract or not newextextract:
            return
        origextension = origextextract.group(1)
        newextension = newextextract.group(1)

        if newextension != ".tmp" and origextension != newextension:
            self.appendcount += 1
            if newextension not in self.newextensions:
                self.newextensions.append(newextension)

    def on_call(self, call, process):
        if not call["status"]:
            return None

        pid = str(process.get("process_id", ""))

        if call["api"].startswith("MoveFileWithProgress"):
            origfile = self.get_argument(call, "ExistingFileName") or ""
            newfile = self.get_argument(call, "NewFileName") or ""
            if (
                "\\appdata\\local\\microsoft\\windows\\explorer\\iconcache_" in origfile.lower()
                and "\\appdata\\local\\microsoft\\windows\\explorer\\iconcachetodelete\\" in newfile.lower()
            ):
                return None
            self._handle_rename(origfile, newfile)

        elif call["api"] == "NtCreateFile":
            if self.get_argument(call, "ExistedBefore") != "yes":
                return None
            filepath = self.get_argument(call, "FileName") or ""
            if self._is_noise_path(filepath, self.handle_noise_paths):
                return None
            handle = self.get_argument(call, "FileHandle")
            if handle and pid:
                if pid not in self.handles_by_pid:
                    self.handles_by_pid[pid] = set()
                self.handles_by_pid[pid].add(handle)

        elif call["api"] == "NtWriteFile":
            pid_handles = self.handles_by_pid.get(pid)
            if not pid_handles:
                return None
            handle = self.get_argument(call, "FileHandle")
            if handle not in pid_handles:
                return None
            file_name = self.get_argument(call, "HandleName") or ""
            if self._is_noise_path(file_name):
                return None
            if file_name in self._overwritten_files:
                return None
            self._overwritten_files.add(file_name)
            self.modifiedexistingcount += 1
            if self.modifiedexistingcount <= 10:
                self.mark_call()
            self.data.append({"overwritten_file": file_name})

        elif call["api"] == "NtSetInformationFile":
            info_class = self.get_argument(call, "FileInformationClass")
            # FileRenameInformation
            if info_class in (10, "10"):
                self._handle_rename(
                    self.get_argument(call, "HandleName") or "",
                    self.get_argument(call, "FileName") or "",
                )
            # FileDispositionInformation — file marked for delete-on-close
            elif info_class in (13, "13"):
                filepath = self.get_argument(call, "HandleName") or ""
                if not filepath or self._is_noise_path(filepath):
                    return None
                if filepath not in self._disposition_deleted:
                    self._disposition_deleted.add(filepath)
                    self.dispositiondeletecount += 1
                    if self.dispositiondeletecount <= 10:
                        self.mark_call()

    def on_complete(self):
        deletedfiles = self.results.get("behavior", {}).get("summary", {}).get("delete_files", [])
        deletedcount = 0
        for deletedfile in deletedfiles:
            if not self._is_noise_path(deletedfile):
                self.data.append({"deleted_file": deletedfile})
                deletedcount += 1

        effective_deletedcount = deletedcount + self.dispositiondeletecount

        if effective_deletedcount > 40:
            self._append_tag("mass_file_deletion", ["OC0001", "C0047"])

        if self.movefilecount > 20:
            self._append_tag("suspicious_file_moves", ["OC0005", "C0027"])

        if self.appendemailcount > 20:
            self._append_tag("appends_email_to_filenames")

        if self.modifiedexistingcount > 30:
            self._append_tag("overwrites_existing_files")

        if self.appendcount > 25:
            if len(self.newextensions) > 15:
                self._append_tag("appends_new_extensions_to_files", ["OC0001", "C0015"])
            else:
                self._append_tag(
                    "appends_new_extensions_to_files({})".format(",".join(sorted(self.newextensions))),
                    ["OC0001", "C0015"],
                )

        # Fire if 2 or more sub-behaviours each exceed a lower watermark,
        # catching ransomware that spreads activity across multiple axes.
        composite_hits = sum(
            [
                effective_deletedcount > 20,
                self.movefilecount > 10,
                self.appendemailcount > 10,
                self.modifiedexistingcount > 15,
                self.appendcount > 12,
            ]
        )
        if composite_hits >= 2:
            self._append_tag("composite_ransomware_file_behaviour")

        if self._behaviour_tags:
            self.ret = True
            self.description = "Exhibits possible ransomware or wiper file modification behavior: " + ", ".join(
                self._behaviour_tags
            )

        return self.ret
