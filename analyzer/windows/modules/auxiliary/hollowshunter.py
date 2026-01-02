import json
import logging
import os
import platform
import shlex
import subprocess

from lib.common.abstracts import Auxiliary
from lib.common.exceptions import CuckooPackageError
from lib.common.results import upload_to_host
from lib.core.config import Config

log = logging.getLogger(__name__)


__author__ = "[Canadian Centre for Cyber Security] @CybercentreCanada"


class HollowsHunter(Auxiliary):
    """Hunting the Hollows"""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.config = Config(cfg="analysis.conf")
        self.enabled = self.config.hollowshunter
        self.do_run = self.enabled
        self.output_dir = "C:\\\\hollowshunter"
        self.startupinfo = subprocess.STARTUPINFO()
        self.startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    def start(self):
        # First figure out what architecture the system in running (64 or 86)
        bin_path = os.path.join(os.getcwd(), "bin")

        if "AMD64" in platform.uname():
            hollowshunter = os.path.join(bin_path, "hh_etw.exe")
        else:
            hollowshunter = os.path.join(bin_path, "hh_etw_x86.exe")

        if not os.path.exists(hollowshunter):
            raise CuckooPackageError(
                "In order to use the HollowsHunter functionality, it " "is required to have HollowsHunter setup with Cuckoo."
            )
        hollowshunter = hollowshunter.replace("\\", "\\\\")
        hh_args = self.options.get("hh_args")
        if not hh_args:
            hh_args = "/loop /data 0"  # Re-add /shellc

        hh_cmd = f"{hollowshunter} {hh_args} /dir {self.output_dir} /mignore capemon.dll;capemon_x64.dll"
        hh_cmd = shlex.split(hh_cmd)
        log.debug(hh_cmd)
        # Start HollowsHunter in the background
        #        subprocess.Popen([hollowshunter, "/loop", "/imp", "/shellc", "/dir", self.output_dir], startupinfo=self.startupinfo)
        subprocess.Popen(hh_cmd, startupinfo=self.startupinfo)

    def stop(self):
        get_all_files = False

        if "hollowshunter" in self.options and self.options["hollowshunter"] == "all":
            get_all_files = True

        # VirtualQuery and VirtualProtect may be FPs
        strings_of_interest = [
            b"This program cannot be run in DOS mode.",
            b"VirtualFree",
            b"VirtualAlloc",
            b"LoadLibrary",
            b"LocalFree",
            b"GetProcAddress",
            b"GetModuleHandle",
            b"AdjustTokenPrivileges",
            b"CheckRemoteDebuggerPresent",
            b"CreateMutex",
            b"EnumProcesses",
            b"EnumProcessModules",
            b"gethostname",
            b"IsNTAdmin",
            b"OpenMutex",
            b"RtlWriteRegistryValue",
            b"VirtualAllocEx",
            b"VirtualProtectEx",
            b"WinExec",
        ]
        files_to_upload = set()
        max_upload = 25 if not get_all_files else 100
        upload_count = 0
        scan_report_json = "scan_report.json"

        for d in os.listdir(self.output_dir):
            if get_all_files:
                path = os.path.join(self.output_dir, d)
                if os.path.isfile(path):
                    files_to_upload.add(path)
                    continue
                for f in os.listdir(path):
                    file_path = os.path.join(path, f)
                    files_to_upload.add(file_path)
                continue

            # Find all files in folders that start with process_*
            if "process_" not in d:
                continue
            dirpath = os.path.join(self.output_dir, d)
            only_files = [f for f in os.listdir(dirpath)]

            modules_of_interest = set()

            # We first care about modules that contain PEs
            if scan_report_json in only_files:
                scan_report_path = os.path.join(dirpath, scan_report_json)
                with open(scan_report_path, "rb") as f:
                    report_json = json.loads(f.read())
                scans = report_json["scans"]
                for scan in scans:
                    if "workingset_scan" in scan:
                        workingset_scan = scan["workingset_scan"]
                        has_pe = workingset_scan["has_pe"]
                        if has_pe:
                            module = workingset_scan["module"]
                            modules_of_interest.add(module)
                            # We definitely want this
                            files_to_upload.add(scan_report_path)

            # Here we will perform a string search for certain key terms in shc files
            for f in only_files:
                filename_suffix = f.split(".")[-1]
                file_path = os.path.join(dirpath, f)

                # 100000% we want this
                if filename_suffix in ["exe", "dll"]:
                    files_to_upload.add(file_path)

                # At this point we only care about shc
                if filename_suffix != "shc":
                    continue

                # No dups!
                if file_path in files_to_upload:
                    continue

                if any(module_of_interest in f for module_of_interest in modules_of_interest):
                    files_to_upload.add(file_path)

                log.debug(file_path)
                try:
                    with open(file_path, "rb") as f:
                        file_contents = f.read()
                    if any(item in file_contents for item in strings_of_interest):
                        # We got a hit!
                        files_to_upload.add(file_path)
                except Exception as e:
                    log.debug(f"Could not read and look for strings of interest in {file_path} due to '{e}'")
                    continue

        # Upload the HollowsHunter files to the host.
        log.debug(files_to_upload)
        for f in files_to_upload:
            if upload_count >= max_upload:
                log.debug("HollowsHunter has uploaded the maximum number of files (%d)" % max_upload)
                return

            # Prepend file name with hh to indicate HollowsHunter
            file_path_list = f.split("\\")
            file_name = file_path_list[-1]
            process = file_path_list[-2]
            dumppath = os.path.join("hollowshunter", "hh_" + process + "_" + file_name)
            log.debug("HollowsHunter Aux Module is uploading %s" % f)
            upload_count += 1
            upload_to_host(f, dumppath)
