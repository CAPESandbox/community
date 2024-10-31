from lib.cuckoo.common.abstracts import Signature


class DetectVirtualizationViaRecentFiles(Signature):
    name = "detect_virtualization_via_recent_files"
    description = "Detects virtualization via checking the last access time of recent files"
    severity = 3
    categories = ["anti-vm"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1497", "T1083"]
    references = [
        "https://www.linkedin.com/posts/malcore_today-we-will-be-continuing-our-vm-detection-activity-7257056918160986115-Ihh9?utm_source=share&utm_medium=member_desktop"
    ]

    filter_apinames = set(["SHGetFolderPathW", "FindFirstFileExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.recents = False
        self.enumerate = False

    def on_call(self, call, _):
        if call["api"] == "SHGetFolderPathW":
            folder = self.get_argument(call, "Folder")
            if folder == "0x00000008":  # CSIDL_RECENT
                if self.pid:
                    self.mark_call()
                self.recents = True

        if call["api"] == "FindFirstFileExW":
            folder = self.get_argument(call, "FileName").lower()
            if "\\windows\\recent\\" in folder:
                if self.pid:
                    self.mark_call()
                self.enumerate = True

    def on_complete(self):
        if self.recents and self.enumerate:
            return True
        return False
