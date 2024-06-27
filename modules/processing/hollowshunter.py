import json
import logging
import os
import re

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)


class HollowsHunter(Processing):
    def parse_report(self, data):
        pid = data["pid"]
        if not self.hh_response.get(pid):
            self.hh_response[pid] = {}
        for key in data.keys():
            if key == "pid":
                continue
            self.hh_response[pid][key] = data[key]
        return self.hh_response

    def run(self):
        self.key = "hollowshunter"
        hh_report_regex = "hh_process_[0-9]{3,}_(dump|scan)_report\.json$"
        report_pattern = re.compile(hh_report_regex)
        hh_path = "%s/hollowshunter/" % self.analysis_path
        if not os.path.exists(hh_path):
            return {}
        hh_items = os.listdir(hh_path)
        self.hh_response = {}
        report_list = list(filter(report_pattern.match, hh_items))
        for report in report_list:
            report_path = os.path.join(hh_path, report)
            try:
                report_contents = open(report_path).read()
                report_json = json.loads(report_contents)
            except Exception as e:
                raise CuckooProcessingError("Failed parsing report %s due to %s" % (report_path, str(e)))
            self.parse_report(report_json)
        return self.hh_response
