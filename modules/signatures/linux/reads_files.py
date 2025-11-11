import logging

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__)


class LinuxReadsFiles(Signature):
    name = "reads_files"
    description = "Reads files from disk"
    os = "linux"
    severity = 1
    categories = ["discovery"]
    authors = ["winson0123"]
    minimum = "1.3"
    evented = True
    ttps = []  # MITRE v6,7,8
    mbcs = []

    filter_apinames = set(["read", "readv", "pread", "preadv", "preadv2", "pread64"])

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
                log.debug(f"LinuxReadsFiles: self._current_call_list[0] = {self._current_call_list[0]}")
                return self._current_call_list[0].split(" ")[1][1:-1]
            except IndexError:
                return None

        return None

    def on_call(self, call, process):
        if call["api"] in self.filter_apinames:
            data = {"ReadFile": self.get_filename(call)}
            if data not in self.data:
                self.loadctr += 1
                self.data.append(data)

    def on_complete(self):
        if self.loadctr > 0:
            return True
