from lib.cuckoo.common.abstracts import Signature


class LinuxDropsFiles(Signature):
    name = "drops_files"
    description = "Drops files onto disk"
    os = "linux"
    severity = 2
    categories = ["dropper"]
    authors = ["winson0123"]
    minimum = "1.3"
    evented = True
    ttps = []  # MITRE v6,7,8
    mbcs = []

    filter_apinames = set(["creat", "open", "openat", "openat2"])
    flags = "O_CREAT"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.loadctr = 0

    def on_call(self, call, process):
        if call["api"] in self.filter_apinames and call["return"] > "-1":
            self.loadctr += 1
            if call["api"] == "creat":
                self.data.append({"DroppedFile": self.get_argument(call, "const char *pathname")[1:-1]})
            elif call["api"] in ["open", "openat", "openat2"]:
                if self.flags in self.get_argument(call, "int flags"):
                    self.data.append({"DroppedFile": self.get_argument(call, "const char *filename")[1:-1]})

    def on_complete(self):
        if self.loadctr > 0:
            return True
