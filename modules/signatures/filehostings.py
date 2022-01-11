import logging
import os

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__)


class Modiloader_APIs(Signature):
    name = "downloads_from_filehosting"
    description = "Downloads probably next stage from public file hosting"
    weight = 3
    severity = 3
    categories = ["loader"]
    authors = ["doomedraven"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.urls = list()

    filter_apinames = set(["InternetOpenUrlA", "WinHttpOpenRequest"])

    def on_call(self, call, process):
        url = False
        if call["api"] == "InternetOpenUrlA":
            url = self.get_argument(call, "URL")
        elif call["api"] == "WinHttpOpenRequest":
            url = self.get_argument(call, "ObjectName")

        if url:
            if url.startswith("https://cdn.discordapp.com/attachments/"):
                self.urls.append(url)
            elif url.startswith("/attachments/"):
                self.urls.append("https://cdn.discordapp.com" + url)
            elif url.startswith("/u/0/uc?id="):
                self.urls.append("https://drive.google.com" + url)
            elif "basecamp.com/p/" in url:
                self.urls.append(url)
            elif url.startswith("https://anonymousfiles.io/"):
                self.urls.append(url)

    def on_complete(self):
        if self.urls:
            self.data.append({"urls": self.urls})
