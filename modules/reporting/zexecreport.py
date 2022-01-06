# Copyright (C) 2022 Quadrant Information Security, written by Zane C. Bowers-Hadley
# This file is part of CAPE Sandbox - https://capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

import subprocess
import logging
import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooReportError

log = logging.getLogger(__name__)

repconf = Config("reporting")

class ZExecReport(Report):
    """Execute the specified command pointed at report.json"""

    def run(self, results):
        """Writes report.
        @param results: CAPE results dict.
        @raise CuckooReportError: if fails to write report.
        """
        try:
            task_id = str(results["info"]["id"])
            path = os.path.join(self.reports_path, "report.json")
            cmd_results = subprocess.run([repconf.zexecreport.command, path], capture_output=True, env={"CAPE_TASK_ID": task_id})
            if cmd_results.returncode != 0:
                log.error("CAPE_TASK_ID=" + task_id + ' command=' + repconf.zexecreport.command + " exit=" + str(cmd_results.returncode) + " stdout=" + cmd_results.stdout.decode('utf-8') + " stderror=" + cmd_results.stderr.decode('utf-8'))
            else:
                log.info("CAPE_TASK_ID=" + task_id + ' command=' + repconf.zexecreport.command + " stdout=" + cmd_results.stdout.decode('utf-8') + " stderror=" + cmd_results.stderr.decode('utf-8'))
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError(f"Error encountered running the specified command: {e}")
