import csv
import logging
import os
import platform
import shlex
import subprocess
from contextlib import suppress
from winreg import HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_DWORD, CreateKeyEx, SetValueEx

from lib.common.abstracts import Auxiliary
from lib.common.exceptions import CuckooPackageError
from lib.common.results import upload_to_host
from lib.core.config import Config

log = logging.getLogger(__name__)


__author__ = "[Canadian Centre for Cyber Security] @CybercentreCanada"


class Autoruns(Auxiliary):
    """Autoruns from sysinternals"""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.config = Config(cfg="analysis.conf")
        self.enabled = self.config.autoruns
        self.output_dir = "C:\\\\autoruns"
        self.output_file_start = "autoruns_start.txt"
        self.output_file_end = "autoruns_end.txt"
        self.output_file_diff = "autoruns.diff"
        self.startupinfo = subprocess.STARTUPINFO()
        self.startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            # reg.exe ADD "HKCU\Software\Sysinternals\Autoruns" /v EulaAccepted /t REG_DWORD /d 1 /f
        with suppress(OSError):
            with CreateKeyEx(HKEY_CURRENT_USER, "Software\Sysinternals\Autoruns", 0, KEY_ALL_ACCESS) as key:
                SetValueEx(key, "EulaAccepted", 0, REG_DWORD, 1)

        bin_path = os.path.join(os.getcwd(), "bin")
        # First figure out what architecture the system in running (64 or 86)
        if "AMD64" in platform.uname():
            autoruns = os.path.join(bin_path, "autorunsc64.exe")
        else:
            autoruns = os.path.join(bin_path, "autorunsc.exe")

        if not os.path.exists(autoruns):
            raise CuckooPackageError(
                "In order to use the Autorun functionality, it "
                "is required to have the appropriate Autorunsc executable in the analyzer/windows/bin/ path."
            )
        autoruns = autoruns.replace("\\", "\\\\")

        run_args = self.options.get("run_args")
        if not run_args:
            # -a : entry selection * for all entries
            # -c : Print output as csv
            # -o : Output file path
            run_args = f"-a * -c -o {self.output_dir}\\\\{self.output_file_end}"

        run_cmd = f"{autoruns} {run_args}"
        self.run_cmd = shlex.split(run_cmd)

    def start(self):

        log.debug(self.run_cmd)
        subprocess.Popen(self.run_cmd, startupinfo=self.startupinfo)

    def stop(self):
        log.debug(self.run_cmd)
        process = subprocess.Popen(self.run_cmd, startupinfo=self.startupinfo)
        process.wait()

        start_elements = []
        end_elements = []
        diff_elements = []
        path_start = os.path.join(self.output_dir, self.output_file_start)
        path_end = os.path.join(self.output_dir, self.output_file_end)
        path_diff = os.path.join(self.output_dir, self.output_file_diff)

        with open(path_start, mode="r") as f:
            reader = csv.DictReader(f, delimiter=",")
            for row in reader:
                start_elements.append(row)
        with open(path_end, mode="r") as f:
            reader = csv.DictReader(f, delimiter=",")
            for row in reader:
                keys = row.keys()
                end_elements.append(row)

        for element in start_elements:
            if element not in end_elements:
                diff_elements.append(f"--,{element}")
        for element in end_elements:
            if element not in start_elements:
                diff_elements.append(f"++,{element}")

        with open(path_diff, mode="w") as f:
            if len(diff_elements) > 0:
                f.write(f"Operation,{keys}\n")
                f.writelines(f"{s}\n" for s in diff_elements)

        files_to_upload = set()

        if os.path.isfile(path_diff):
            try:
                if os.path.getsize(path_diff) > 0:
                    files_to_upload.add(path_diff)
                else:
                    log.debug("Diff file is empty")
            except Exception as e:
                log.debug("Diff file doesn't seem to exist: %s", str(e))

        # Upload the autoruns diff file to the host.
        log.debug(files_to_upload)
        for f in files_to_upload:
            # Prepend file name with autoruns to indicate autoruns
            file_path_list = f.split("\\")
            file_name = file_path_list[-1]
            dumppath = os.path.join("autoruns", file_name)
            log.debug("Autoruns Aux Module is uploading %s" % f)
            upload_to_host(f, dumppath)
