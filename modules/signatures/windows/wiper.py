# Copyright (C) 2022 Kevin Ross
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
 
 
class WiperZeroedBytes(Signature):
    name = "wiper_zeroedbytes"
    description = "Overwrites files with zeroed bytes indicative of a wiper"
    severity = 3
    categories = ["wiper", "ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1485", "T1561", "T1561.001"]
    mbcs = ["C0052", "F0014"]
 
    filter_apinames = set(["NtWriteFile"])
 
    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        # Number of distinct files that must be zero-wiped before firing.
        self.threshold = 10
        # Minimum buffer length to consider. Short zero writes occur during
        # normal file operations (e.g. flushing headers) and are not indicative.
        self.min_buffer_length = 30
        # Compiled once. Matches buffers containing only null bytes or their
        # dot-placeholder representation from CAPE's safe-string encoding.
        self.zero_pattern = re.compile(r"^[\x00\.]+$")
        # Track each wiped file path exactly once using a set, preventing
        # the string-comparison bug where revisiting a file between two others
        # would count it multiple times.
        self.wiped_files = set()
        # Paths where zero-byte writes are normal and should be ignored.
        self.noise_paths = [
            "\\device\\null",
            "\\device\\clfs",
            "pagefile.sys",
            "hiberfil.sys",
            "swapfile.sys",
        ]
 
    def on_call(self, call, process):
        if not call["status"]:
            return None
 
        filepath = self.get_raw_argument(call, "HandleName")
        if not filepath:
            return None
 
        if filepath in self.wiped_files:
            return None
 
        fl = filepath.lower()
        if any(n in fl for n in self.noise_paths):
            return None
 
        buff = self.get_raw_argument(call, "Buffer")
        if not buff or len(buff) < self.min_buffer_length:
            return None
 
        if self.zero_pattern.match(buff):
            self.wiped_files.add(filepath)
            if self.pid:
                self.mark_call()
 
    def on_complete(self):
        count = len(self.wiped_files)
        if count > self.threshold:
            self.data.append({"files_wiped": count})
            return True
        return False
 
 
class WiperZeroedBytesLargeFile(Signature):
    name = "wiper_zeroedbytes_large_file"
    description = "Writes a large zero-byte payload to a single file, consistent with staging a corrupt firmware image or destroying a large data file"
    severity = 3
    categories = ["wiper"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1485", "T1495", "T1561.001"]
    mbcs = ["C0052", "F0014"]
 
    filter_apinames = set(["NtWriteFile"])
 
    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        # Single write must be at least 1MB of zeros to fire.
        self.single_write_threshold = 1048576
        self.zero_pattern = re.compile(r"^[\x00\.]+$")
        self.noise_paths = [
            "\\device\\null",
            "\\device\\clfs",
            "pagefile.sys",
            "hiberfil.sys",
            "swapfile.sys",
        ]
        self.hits = []
 
    def on_call(self, call, process):
        if not call["status"]:
            return None
 
        filepath = self.get_raw_argument(call, "HandleName")
        if not filepath or filepath in self.hits:
            return None
 
        fl = filepath.lower()
        if any(n in fl for n in self.noise_paths):
            return None
 
        try:
            length = int(self.get_raw_argument(call, "Length") or 0)
        except (ValueError, TypeError):
            return None
 
        if length < self.single_write_threshold:
            return None
 
        buff = self.get_raw_argument(call, "Buffer")
        if not buff:
            return None
 
        if self.zero_pattern.match(buff):
            self.hits.append(filepath)
            self.data.append({"file": filepath, "zeroed_bytes": length})
            if self.pid:
                self.mark_call()
 
    def on_complete(self):
        return bool(self.hits)


class WiperDiskFillAttack(Signature):
    name = "wiper_disk_fill_attack"
    description = "Writes large amounts of data to a file at the root of a drive letter, potential wiper destruction"
    severity = 3
    confidence = 60
    categories = ["wiper", "impact"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1485", "T1561"]
    mbcs = ["OB0010", "E1485"]

    filter_apinames = set(["NtWriteFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        # Minimum single write size before a write to drive root is considered
        # suspicious. Legitimate I/O to drive root rarely uses large chunks.
        self.write_size_threshold = 524288      # 512KB per write
        # Total bytes that must be written before the signature fires.
        # Single large writes may be coincidental; sustained fill is the signal.
        self.total_threshold = 10485760         # 10MB total
        # Drive-root path pattern: exactly one path component below the drive
        # letter, e.g. C:\FILL3820.tmp but NOT C:\Users\...\file.tmp
        self.drive_root_pattern = re.compile(r"^[A-Za-z]:\\[^\\]+$")
        # {filename_lower: total_bytes}
        self.root_write_totals = {}

    def on_call(self, call, process):
        if not call["status"]:
            return None

        hname = self.get_argument(call, "HandleName") or ""
        if not hname:
            return None

        if not self.drive_root_pattern.match(hname):
            return None

        try:
            length = int(self.get_raw_argument(call, "Length") or 0)
        except (ValueError, TypeError):
            return None

        if length < self.write_size_threshold:
            return None

        key = hname.lower()
        self.root_write_totals[key] = self.root_write_totals.get(key, 0) + length

        if self.root_write_totals[key] >= self.total_threshold:
            if self.root_write_totals[key] - length < self.total_threshold:
                self.mark_call()

    def on_complete(self):
        for fname, total in self.root_write_totals.items():
            if total >= self.total_threshold:
                self.data.append({
                    "fill_file": fname,
                    "total_mb": round(total / 1048576.0, 1),
                })
        return bool(self.data)


class WiperCommandLineDiskDestruction(Signature):
    name = "wiper_commandline_disk_destruction"
    description = "Executes commands associated with disk or filesystem destruction including format, cipher overwrite, or direct disk manipulation utilities"
    severity = 3
    confidence = 70
    categories = ["wiper", "impact"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1485", "T1561.001"]
    mbcs = ["OB0010", "E1485"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        # format.exe /y : bypasses confirmation prompt on volume format
        # cipher /w     : overwrites free space with random data (anti-forensics)
        # sdelete -p    : Sysinternals secure delete with overwrite passes
        # diskpart       : interactive disk management tool, used by wipers for
        #                  partition table destruction (clean, format, delete)
        # dd if=/dev/zero: Unix-style zero fill via Windows ports (e.g. msys)
        self.destruction_patterns = [
            (r"format\s+[a-z]:", "format_volume"),
            (r"format(\.exe)?.*\/y", "format_volume_noconfirm"),
            (r"cipher(\.exe)?\s+\/w", "cipher_free_space_wipe"),
            (r"sdelete.*\-p\s*\d", "sdelete_overwrite"),
            (r"diskpart.*clean", "diskpart_clean"),
            (r"diskpart.*delete\s+partition", "diskpart_delete_partition"),
            (r"diskpart.*convert", "diskpart_convert"),
            (r"erase\s+\/[fp].*[a-z]:", "erase_filesystem"),
            (r"del\s+\/[sfq].*\\windows\\system32", "mass_delete_system32"),
        ]

    def run(self):
        ret = False
        commands = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in commands:
            lower = cmdline.lower()
            for pattern, label in self.destruction_patterns:
                if re.search(pattern, lower):
                    self.data.append({"command": cmdline, "technique": label})
                    ret = True
                    break
        return ret


class WiperEPMNTDRVRawDisk(Signature):
    name = "wiper_epmntdrv_rawdisk"
    description = "Writes directly to the EldoS RawDisk partition driver device (EPMNTDRV), the sector-level wiping technique used by some wipers to destroy disk partitions without standard filesystem access"
    severity = 3
    confidence = 90
    categories = ["wiper", "bootkit"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1485", "T1561.002", "T1542.003"]
    mbcs = ["OB0010", "E1485", "F0013"]
 
    filter_apinames = set(["NtCreateFile", "NtOpenFile", "NtWriteFile"])
 
    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.epmntdrv_fragments = [
            "epmntdrv",
        ]
        self.opened = False
        self.write_count = 0
        self.total_bytes = 0
 
    def on_call(self, call, process):
        if not call["status"]:
            return None
 
        if call["api"] in ("NtCreateFile", "NtOpenFile"):
            fname = (self.get_argument(call, "FileName") or "").lower()
            if any(f in fname for f in self.epmntdrv_fragments):
                self.opened = True
                self.data.append({"device_opened": self.get_argument(call, "FileName")})
                self.mark_call()
 
        elif call["api"] == "NtWriteFile":
            hname = (self.get_argument(call, "HandleName") or "").lower()
            if any(f in hname for f in self.epmntdrv_fragments):
                self.write_count += 1
                try:
                    self.total_bytes += int(self.get_raw_argument(call, "Length") or 0)
                except (ValueError, TypeError):
                    pass
                if self.write_count <= 3:
                    self.mark_call()
 
    def on_complete(self):
        if self.opened or self.write_count > 0:
            if self.write_count:
                self.data.append({
                    "sector_write_count": self.write_count,
                    "total_mb_written": round(self.total_bytes / 1048576.0, 1),
                })
            return True
        return False
 
 
class TransientKernelDriver(Signature):
    name = "transient_kernel_driver"
    description = "Installs a kernel driver and deletes it within the same run, indicative of BYOVD to bypass EDR or provide disk access for wipers and then removing forensic traces of the driver"
    severity = 3
    confidence = 80
    categories = ["wiper", "bootkit", "byovd"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1485", "T1014", "T1543.003"]
    mbcs = ["OB0010", "E1485"]
 
    filter_apinames = set(["CreateServiceW", "StartServiceW", "DeleteService",
                           "ControlService", "NtUnloadDriver"])
 
    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        # SERVICE_KERNEL_DRIVER = 0x1, SERVICE_FILE_SYSTEM_DRIVER = 0x2
        self.driver_service_types = {"0x00000001", "0x00000002", "1", "2"}
        self.installed_drivers = {}  # {service_name: binary_path}
        self.started_drivers = set()
        self.deleted_drivers = set()
 
    def on_call(self, call, process):
        if call["api"] == "CreateServiceW" and call["status"]:
            svc_type = self.get_argument(call, "ServiceType") or ""
            if svc_type in self.driver_service_types:
                svc_name = (self.get_argument(call, "ServiceName") or "").lower()
                binary   = self.get_argument(call, "BinaryPathName") or ""
                if svc_name:
                    self.installed_drivers[svc_name] = binary
 
        elif call["api"] == "StartServiceW" and call["status"]:
            svc_name = (self.get_argument(call, "ServiceName") or "").lower()
            if svc_name in self.installed_drivers:
                self.started_drivers.add(svc_name)
 
        elif call["api"] in ("DeleteService", "NtUnloadDriver"):
            svc_name = (self.get_argument(call, "ServiceName") or
                        self.get_argument(call, "lpDriverName") or
                        self.get_argument(call, "DriverServiceName") or "").lower()
            if "\\" in svc_name:
                svc_name = svc_name.split("\\")[-1]
            if svc_name in self.installed_drivers:
                self.deleted_drivers.add(svc_name)
                self.mark_call()
 
    def on_complete(self):
        transient = self.deleted_drivers.intersection(self.installed_drivers)
        if not transient:
            return False
        for svc in transient:
            self.data.append({
                "driver_service": svc,
                "binary_path": self.installed_drivers[svc],
                "was_started": svc in self.started_drivers,
            })
        return True
 
 
class WiperRecycleBinDestruction(Signature):
    name = "wiper_recycle_bin_destruction"
    description = "Deletes the Recycle Bin directory structure, preventing recovery of previously deleted files"
    severity = 3
    confidence = 70
    categories = ["wiper", "impact"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1485", "T1070"]
    mbcs = ["OB0010", "E1485"]
 
    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.threshold = 2
 
    def run(self):
        summary = self.results.get("behavior", {}).get("summary", {})
        delete_files = summary.get("delete_files", [])
        write_files  = summary.get("write_files",  [])
        sid_deleted = {
            f for f in delete_files
            if re.search(r"\$recycle\.bin\\S-\d", f, re.IGNORECASE)
        }
        recycle_written = {
            f for f in write_files
            if re.search(r"\$recycle\.bin\\S-\d", f, re.IGNORECASE)
        }
 
        if len(sid_deleted) >= self.threshold:
            for f in sorted(sid_deleted):
                self.data.append({"recycle_bin_deleted": f})
            return True
 
        if len(recycle_written) >= self.threshold:
            for f in sorted(recycle_written):
                self.data.append({"recycle_bin_corrupted": f})
            return True
 
        return False
 
 
class WiperActivityLog(Signature):
    name = "wiper_activity_log"
    description = "Writes a human-readable disk destruction activity log to a file, a technique used by some wipers to record wiping progress and failure states"
    severity = 3
    confidence = 70
    categories = ["wiper", "impact"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1485"]
    mbcs = ["OB0010", "E1485"]
 
    filter_apinames = set(["NtWriteFile"])
 
    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        # Plain-text strings written to a log file by the wiper to record
        # its own disk destruction activity. These are output by the wiper
        # itself and are not part of the target files being destroyed.
        self.wiper_log_strings = [
            "start erasing",
            "erasing drive",
            "erasing volume",
            "erasing physical",
            "wiping drive",
            "wiping volume",
            "getting drives",
            "physical drives:",
            "logical drives:",
            "system physical drive",
            "start wiping",
            "disk wipe",
        ]
        self.system_log_paths = [
            "\\windows\\",
            "\\program files\\",
            "\\programdata\\microsoft\\",
        ]
        self.hits = []
 
    def on_call(self, call, process):
        if not call["status"]:
            return None
 
        hname = (self.get_argument(call, "HandleName") or "").lower()
        if not hname:
            return None
 
        # Must be writing to a log/text file
        if not any(hname.endswith(ext) for ext in (".log", ".txt", ".out")):
            return None
 
        # Skip standard Windows log paths
        if any(p in hname for p in self.system_log_paths):
            return None
 
        buf = (self.get_argument(call, "Buffer") or "").lower()
        if not buf:
            return None
 
        for pattern in self.wiper_log_strings:
            if pattern in buf:
                entry = self.get_argument(call, "HandleName")
                if entry not in self.hits:
                    self.hits.append(entry)
                    self.data.append({
                        "log_file": entry,
                        "wiper_string_matched": pattern,
                    })
                    self.mark_call()
                break
 
    def on_complete(self):
        return bool(self.hits)
 
 
class WiperRmDirDrive(Signature):
    name = "wiper_rmdir_drive"
    description = "Executes rmdir recursively against an entire drive root, indicative of wipers deleting all files on the system drive via a single command"
    severity = 3
    confidence = 80
    categories = ["wiper", "impact"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1485", "T1561"]
    mbcs = ["OB0010", "E1485"]
 
    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.rmdir_pattern = re.compile(
            r"\b(rmdir|rd)\b.*/s.*[a-z]:\\?\s*$|"
            r"\b(rmdir|rd)\b\s+[a-z]:\\?\s+/s",
            re.IGNORECASE
        )
 
    def run(self):
        commands = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmd in commands:
            if self.rmdir_pattern.search(cmd):
                self.data.append({"command": cmd})
        return bool(self.data)


class WiperFileEofTruncation(Signature):
    name = "wiper_file_eof_truncation"
    description = "Truncates files to zero bytes via NtSetInformationFile FileEndOfFileInformation, indicative of wiper file destruction"
    severity = 3
    confidence = 80
    categories = ["wiper", "impact"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1485", "T1561"]
    mbcs = ["OB0010", "E1485", "C0052"]

    filter_apinames = set(["NtSetInformationFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.target_class = 14
        self.noise_paths = [
            "\\windows\\",
            "\\program files\\",
            "\\programdata\\microsoft\\",
            "\\device\\",
        ]
        self.truncated_files = []
        self.threshold = 3

    def on_call(self, call, process):
        if not call["status"]:
            return None

        try:
            info_class = int(self.get_argument(call, "FileInformationClass") or 0)
        except (ValueError, TypeError):
            return None

        if info_class != self.target_class:
            return None

        filepath = self.get_argument(call, "HandleName") or ""
        if not filepath:
            return None

        fl = filepath.lower()
        if any(n in fl for n in self.noise_paths):
            return None

        file_info = self.get_argument(call, "FileInformation") or ""
        # FileEndOfFileInformation is an 8-byte LARGE_INTEGER.
        # Value of all nulls or \\x00 sequences = truncate to zero.
        if file_info and file_info.replace("\\x00", "").replace("\\\\x00", "").strip():
            return None

        if filepath not in self.truncated_files:
            self.truncated_files.append(filepath)
            if self.pid:
                self.mark_call()
