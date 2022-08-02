import logging
import os
import platform
import subprocess
import threading

from lib.common.abstracts import Auxiliary
from lib.common.exceptions import CuckooPackageError
from lib.common.results import upload_to_host
from lib.core.config import Config

log = logging.getLogger(__name__)

__author__ = "@FernandoDoming"
__version__ = "1.0.1"


class Sysmon(threading.Thread, Auxiliary):
    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.enabled = config.sysmon
        self.startupinfo = subprocess.STARTUPINFO()
        self.startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    def clear_log(self):
        try:
            subprocess.call(
                ("C:\\Windows\\System32\\wevtutil.exe", "clear-log", "microsoft-windows-sysmon/operational"),
                startupinfo=self.startupinfo,
            )
        except Exception as e:
            log.error("Error clearing Sysmon events - %s", e)

    def collect_logs(self):
        sysmon_xml_path = "C:\\sysmon.xml"
        try:
            subprocess.call(
                (
                    "C:\\Windows\\System32\\wevtutil.exe",
                    "query-events",
                    "microsoft-windows-sysmon/operational",
                    "/rd:true",
                    "/e:Events",
                    "/format:xml",
                ),
                startupinfo=self.startupinfo,
                stdout=open(sysmon_xml_path, "w"),
            )
        except Exception as e:
            log.error("Could not create sysmon log file - %s", e)

        if os.path.exists(sysmon_xml_path):
            upload_to_host(sysmon_xml_path, "sysmon/sysmon.xml")
        else:
            log.error("Sysmon log file not found in guest machine")

    def start(self):
        if not self.enabled:
            return False

        self.clear_log()

        # First figure out what architecture the system in running (x64 or x86)
        bin_path = os.path.join(os.getcwd(), "bin")

        if "Windows" in platform.uname():
            if "AMD64" in platform.uname():
                sysmon = os.path.join(bin_path, "SMaster64.exe")
            else:
                sysmon = os.path.join(bin_path, "SMaster32.exe")
        # TODO: Platform is Linux, add support for https://github.com/Sysinternals/SysmonForLinux
        else:
            self.enabled = False
            return False

        config_file = os.path.join(bin_path, "sysmonconfig-export.xml")
        if not os.path.exists(sysmon) or not os.path.exists(config_file):
            raise CuckooPackageError(
                "In order to use the Sysmon functionality, it "
                "is required to have the sysmon(64|32).exe file and "
                "sysmonconfig.xml file in the bin path."
            )

        # Start Sysmon in the background
        subprocess.call([sysmon, "-accepteula", "-n", "-i", config_file], startupinfo=self.startupinfo)

    def stop(self) -> bool:
        if self.enabled:
            self.collect_logs()
            return True
        return False
