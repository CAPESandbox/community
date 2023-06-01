from datetime import datetime
import logging
import os
import subprocess
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.exceptions import CuckooPackageError
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

__author__ = "@cccs-kevin"
__version__ = "1.0.0"

SYSLOG_PATH = "/var/log/syslog"
SYSLOGVIEW_PATH = "/opt/sysmon/sysmonLogView"
SYSMON_LOG_NAME = "sysmon.data"
SYSMON_LOG_PATH = "/tmp/sysmon.data"

def is_sysmon_installed() -> bool:
    # SysmonForLinux must be installed manually on the VM
    # https://github.com/Sysinternals/SysmonForLinux/blob/main/INSTALL.md
    completed_process = subprocess.run(["dpkg-query", "-l", "sysmonforlinux"], capture_output=True)
    if b"dpkg-query: no packages found matching sysmonforlinux" in completed_process.stdout:
        return False
    else:
        return True


class Sysmon(Thread, Auxiliary):
    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.enabled = config.sysmon_linux
        self.start_time = None
        self.end_time = None

    def collect_logs(self):
        args = [
            "journalctl",
            "--no-pager",
            "--since",
            self.start_time,
            "--until",
            self.end_time,
            "-u",
            "sysmon.service",
            "-g",
            "\"Linux-Sysmon\""
        ]
        try:
            completed_process = subprocess.run(
                args,
                stdout=open(SYSMON_LOG_PATH, "wb"),
            )
            log.debug(completed_process.args)
        except Exception as e:
            log.error("Could not create sysmon log file - %s", e)

        if os.path.exists(SYSMON_LOG_PATH):
            upload_to_host(SYSMON_LOG_PATH, f"sysmon/{SYSMON_LOG_NAME}")
        else:
            log.error("Sysmon log file not found in guest machine")

    def start(self):
        if not self.enabled:
            return False

        if not is_sysmon_installed():
            raise CuckooPackageError(
                "In order to use the Sysmon functionality, it "
                "is required to have the sysmonforlinux installed on the VM. "
                "See https://github.com/Sysinternals/SysmonForLinux/blob/main/INSTALL.md"
            )

        # Recommended options for the sysmon configuration include
        # https://github.com/microsoft/MSTIC-Sysmon/tree/main/linux/configs,
        # specifically "collect-all.xml" (https://github.com/microsoft/MSTIC-Sysmon/blob/main/linux/configs/collect-all.xml)
        # and "main.xml" (https://github.com/microsoft/MSTIC-Sysmon/blob/main/linux/configs/main.xml)
        # You must rename the config file to "sysmonconfig-export.xml"
        bin_path = os.path.join(os.getcwd(), "bin")
        config_file = os.path.join(bin_path, "sysmonconfig-export.xml")

        if not os.path.exists(config_file):
            raise CuckooPackageError(
                "In order to use the Sysmon functionality, it "
                "is required to have the sysmonconfig.xml file in the bin path."
            )

        # Start Sysmon service
        completed_process = subprocess.run(["sudo", "sysmon", "-accepteula", "-i", config_file], capture_output=True)
        log.debug(completed_process.stdout)
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def stop(self) -> bool:
        if self.enabled:
            self.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.collect_logs()
            return True
        return False
