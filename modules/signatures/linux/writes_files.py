import logging

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__)

class LinuxWritesFiles(Signature):
    name = "writes_files"
    description = "Writes to files on disk"
    os = "linux"
    severity = 2
    categories = ["evasion"]
    authors = ["winson0123"]
    minimum = "1.3"
    evented = True
    ttps = []  # MITRE v6,7,8
    mbcs = []

    filter_apinames = set(
        [
            "write",
            "pwrite64",
            "writev",
            "pwritev",
            "pwritev2",
        ]
    )

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
            try:
                log.debug(f"LinuxWritesFiles: self._current_call_list[0] = {self._current_call_list[0]}")
                return self._current_call_list[0].split(" ")[1][1:-1]
            except IndexError:
                return None
        return None

    def on_call(self, call, process):
        if call["api"] in self.filter_apinames and call["return"] > "-1":
            data = {"WriteFile": self.get_filename(call)}
            if data not in self.data:
                self.loadctr += 1
                self.data.append(data)

    def on_complete(self):
        if self.loadctr > 0:
            return True
