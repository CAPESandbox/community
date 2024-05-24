# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class StealthNetwork(Signature):
    name = "stealth_network"
    description = "Network activity detected but not expressed in monitor API logs"
    severity = 1
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True
    confidence = 30

    filter_categories = set(["network"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.foundnetwork = False

    def on_call(self, call, process):
        self.foundnetwork = True
        if self.pid:
            self.mark_call()

    def on_complete(self):
        initialproc = self.get_initial_process()
        if "network" in self.results and initialproc and not self.foundnetwork:
            hosts = False
            for key in ["hosts", "domains"]:
                for host in self.results["network"].get(key, []):
                    hosts = True
                    if key == "hosts":
                        self.data.append({"ip": host["ip"]})
                    else:
                        self.data.append({"domain": host["domain"]})
            if hosts:
                return True
        return False
