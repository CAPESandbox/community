import csv
import logging
import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

__author__ = "[Canadian Centre for Cyber Security] @CybercentreCanada"
__version__ = "1.0.0"


class Autoruns(Processing):
    def run(self):
        self.key = "autoruns"
        autoruns_dir = os.path.join(self.analysis_path, "autoruns")
        autoruns_data_path = os.path.join(autoruns_dir, "autoruns.diff")

        if os.path.exists(autoruns_data_path):
            autoruns_path = autoruns_data_path
        else:
            return

        data = {}
        try:
            with open(autoruns_path, "r") as f:
                # Operation,Time,Entry Location,Entry,Enabled,Category,Profile,Description,Company,Image Path,Version,Launch String
                reader = csv.DictReader(f, delimiter=",")
                count = 0
                for row in reader:
                    count += 1
                    data[str(count)] = str(row)

            if count == 0:
                data = None

        except Exception as e:
            raise CuckooProcessingError(f"Failed parsing {autoruns_path}: {e}")

        return data
