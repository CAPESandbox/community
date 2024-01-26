import logging
import os
import csv

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

__author__ = "[Canadian Centre for Cyber Security] @CybercentreCanada"
__version__ = "1.0.0"


class Sysmon(Processing):
    def run(self):
        self.key = "autorun"
        autorun_dir = os.path.join(self.analysis_path, "autorun")
        autorun_data_path = os.path.join(autorun_dir, "autorun_autorun.diff")

        if os.path.exists(autorun_data_path):
            autorun_path = autorun_data_path
        else:
            return

        data = {
        }
        try:
            with open(autorun_path, "r") as f:
                #Time,Entry Location,Entry,Enabled,Category,Profile,Description,Company,Image Path,Version,Launch String
                reader = csv.DictReader(f, delimiter=",")
                count = 0
                for row in reader:
                    count += 1
                    data[str(count)] = row

            if count == 0:
                data = None
                    


        except Exception as e:
            raise CuckooProcessingError(f"Failed parsing {autorun_path}: {e}")

        return data
