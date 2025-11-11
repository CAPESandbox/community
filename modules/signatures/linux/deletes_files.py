import logging

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__)

class LinuxDeletesFiles(Signature):
    name = "deletes_files"
    description = "Deletes files from disk"
    os = "linux"
    severity = 3
    categories = ["persistence", "stealth"]
    authors = ["winson0123"]
    minimum = "1.3"
    evented = True
    ttps = ["T1107"]  # MITRE v6
    ttps += ["T1070", "T1070.004"]  # MITRE v7,8
    mbcs = ["OB0006", "F0007"]
    mbcs += ["OC0001", "C0047"]  # micro-behaviour

    filter_apinames = set(
        [
            "truncate",
            "ftruncate",
            "open",
            "openat",
            "openat2",
            "unlink",
            "unlinkat",
        ]
    )
    flags = "O_TRUNC"  # truncating makes file empty, take as a form of deletion

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.loadctr = 0

    def get_filename(self, call):
        """Retrieves the filename of read-related API call.
        @param call: API call object.
        @return: value of the required argument.
        """
        # Check if the call passed to it was cached already.
        # If not, we can start caching it and store a copy converted to a dict.
        if call is not self._current_call_cache:
            self._current_call_cache = call
            self._current_call_list = [argument["value"] for argument in call["arguments"]]

        # Return the filename from retrieved from the api call.
        if self._current_call_list:
            log.debug(f"LinuxDeletedFiles: self._current_call_list[0] = {self._current_call_list[0]}")
            try:
                return self._current_call_list[0].split(" ")[1][1:-1]
            except IndexError:
                return None

        return None

    def on_call(self, call, process):
        if call["api"] in ["truncate", "ftruncate"] and call["return"] == "0":
            self.loadctr += 1
            if call["api"] == "truncate":
                self.data.append({"DeletedFile": self.get_argument(call, "const char *path")})
            if call["api"] == "ftruncate":
                self.data.append({"DeletedFile": self.get_filename(call)})
        if call["api"] in ["unlink", "unlinkat"] and call["return"] == "0":
            self.loadctr += 1
            self.data.append({"DeletedFile": self.get_argument(call, "const char *pathname")})
        if call["api"] == "open" and call["return"] > "-1":
            if self.flags in self.get_argument(call, "int flags"):
                self.loadctr += 1
                self.data.append({"DeletedFile": self.get_filename(call)})
        if call["api"] == "openat" and call["return"] > "-1":
            if self.flags in self.get_argument(call, "int flags"):
                self.loadctr += 1
                self.data.append({"DeletedFile": self.get_argument(call, "const char *filename")})
        if call["api"] == "openat2" and call["return"] > "-1":
            if self.flags in self.get_argument(call, "struct open_how *how"):
                self.loadctr += 1
                self.data.append({"DeletedFile": self.get_argument(call, "const char *filename")})

    def on_complete(self):
        if self.loadctr > 0:
            return True
