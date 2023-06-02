import logging
import os
import re

import xmltodict
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

__author__ = "@FernandoDoming,@cccs-kevin"
__version__ = "2.0.0"


def parseXmlToJson(xml):
    return {child.tag: parseXmlToJson(child) if list(child) else child.text or "" for child in list(xml)}


def massage_linux_data(journalctl_output: list) -> bytes:
    # Remove the date+hostname+service+pid from each line
    massaged_output = []
    for line in journalctl_output:
        if b": <" in line:
            _, content = line.split(b": <")
            refined_content = b"<" + content
            massaged_output.append(refined_content.strip())

    return b"<Events>" + b"\n".join(massaged_output) + b"</Events>"


class Sysmon(Processing):
    def remove_noise(self, data):
        filtered_proc_creations_re = (
            r"C:\\Windows\\System32\\wevtutil\.exe\s+clear-log\s+microsoft-windows-(sysmon|powershell)\/operational",
            r"bin\\is32bit.exe",
            r"bin\\inject-(?:x86|x64).exe",
            r"C:\\Windows\\System32\\wevtutil.exe\s+query-events microsoft-windows-powershell\/operational\s+\/rd:true\s+\/e:root\s+\/format:xml\s+\/uni:true",
            r"C:\\Windows\\System32\\wevtutil.exe\s+query-events\s+microsoft-windows-sysmon\/operational\s+\/format:xml",
        )

        filtered = []
        for event in data:
            is_filtered = False
            if event["System"]["EventID"] == "1":
                for p in filtered_proc_creations_re:
                    cmdline = event["EventData"]["Data"][9].get("#text")
                    if cmdline and re.search(p, cmdline):
                        log.info("Supressed %s because it is noisy", cmdline)
                        is_filtered = True

            if not is_filtered:
                filtered.append(event)

        return filtered

    def run(self):
        self.key = "sysmon"
        sysmon_dir = os.path.join(self.analysis_path, "sysmon")
        windows_sysmon_data_path = os.path.join(sysmon_dir, "sysmon.xml")
        linux_sysmon_data_path = os.path.join(sysmon_dir, "sysmon.data")

        # Windows size check
        if os.path.exists(windows_sysmon_data_path) and os.path.getsize(windows_sysmon_data_path) < 100:
            return
        # Linux size check
        elif os.path.exists(linux_sysmon_data_path) and os.path.getsize(linux_sysmon_data_path) < 100:
            return
        # General file check
        elif not os.path.exists(windows_sysmon_data_path) and not os.path.exists(linux_sysmon_data_path):
            return

        # Figure out which sysmon data file we will be using
        sysmon_path = None
        windows = False
        linux = False
        if os.path.exists(windows_sysmon_data_path):
            sysmon_path = windows_sysmon_data_path
            windows = True
        elif os.path.exists(linux_sysmon_data_path):
            sysmon_path = linux_sysmon_data_path
            linux = True
        else:
            return

        data = None
        try:
            if windows:
                xml = open(sysmon_path, "rb").read()
                xml = xml.decode("latin1").encode("utf8")
                data = xmltodict.parse(xml)["Events"]["Event"]
            elif linux:
                journalctl_output = open(sysmon_path, "rb").readlines()
                xml = massage_linux_data(journalctl_output)
                data = xmltodict.parse(xml)["Events"]["Event"]
            else:
                return
        except Exception as e:
            raise CuckooProcessingError(f"Failed parsing {sysmon_path}: {e}")

        return self.remove_noise(data)
