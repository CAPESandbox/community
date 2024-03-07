# Copyright (C) 2015 KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class AntiSandboxSleep(Signature):
    name = "antisandbox_sleep"
    description = "A process attempted to delay the analysis task."
    severity = 2
    categories = ["anti-sandbox"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True
    mbcs = ["OB0001", "B0007", "B0007.008"]

    filter_apinames = set(["NtDelayExecution"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.sleeps = []

    def on_call(self, call, process):
        if call["api"] == "NtDelayExecution":
            sleepy = self.get_argument(call, "Milliseconds")
            if sleepy is not None:
                current_proc = process["process_name"]
                skip = self.get_argument(call, "Status")
                if skip and skip == "Infinite":
                    return None
                if skip and skip != "Skipped":
                    skip = "Slept"
                new = (current_proc, sleepy, skip)
                self.sleeps.append(new)
                if self.pid:
                    self.mark_call()
        return None

    def on_complete(self):
        ret = False
        proc_whitelist = [
            "dwm.exe",
            "adobearm.exe",
            "iexplore.exe",
            "acrord32.exe",
            "winword.exe",
            "excel.exe",
            "splwow64.exe",
            "powershell.exe",
            "outlook.exe",
        ]
        procs = dict()
        for pname, sleep, skip in self.sleeps:
            if pname.lower() not in proc_whitelist:
                if pname not in procs.keys():
                    procs[pname] = dict()
                    procs[pname]["Attempted"] = 0
                    procs[pname]["Actual"] = 0
                procs[pname]["Attempted"] += int(sleep)
                if skip == "Slept":
                    procs[pname]["Actual"] += int(sleep)

        for process in procs:
            if procs[process]["Attempted"] >= 250000:
                ret = True
                actual = str(procs[process]["Actual"] / 1000)
                attempted = str(procs[process]["Attempted"] / 1000)
                self.data.append(
                    {
                        "note": "%s tried to sleep %s seconds, actually delayed analysis time by %s seconds"
                        % (process, attempted, actual)
                    }
                )
            if procs[process]["Attempted"] >= 2100000:
                self.severity = 3
                self.description = "A process attempted to delay the analysis task by a long amount of time."

        return ret
