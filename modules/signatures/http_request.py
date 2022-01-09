#
# Based on internet_request.py by KillerInstinct
#

from lib.cuckoo.common.abstracts import Signature

domain_passlist = []

try:
    from data.safelist.domains import domain_passlist
except ImportError:
    print("Please update CAPE from main repo")


class HTTP_Request(Signature):
    name = "http_request"
    description = "Performs HTTP requests potentially not found in PCAP."
    severity = 2
    categories = ["network"]
    authors = ["enzok", "ditekshen"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.request = dict()
        self.lasthost = str()
        self.urls = list()

    filter_apinames = set(
        [
            "HttpOpenRequestA",
            "HttpOpenRequestW",
            "InternetConnectA",
            "InternetConnectW",
            "WinHttpGetProxyForUrl",
            "InternetOpenUrlW",
            "InternetOpenUrlA",
        ]
    )

    def on_call(self, call, process):
        if call["api"].startswith("InternetConnect"):
            host = self.get_argument(call, "ServerName")
            port = self.get_argument(call, "ServerPort")
            self.lasthost = host
            if host in domain_passlist:
                return None
            if host not in self.request:
                self.request[host] = dict()
                self.request[host]["uris"] = list()
            self.request[host]["curhandle"] = str(call["return"])
            self.request[host]["port"] = port
        elif call["api"].startswith("HttpOpenRequest"):
            handle = str(self.get_argument(call, "InternetHandle"))
            # Sanity check
            if self.lasthost in domain_passlist:
                return None
            if handle == self.request[self.lasthost]["curhandle"]:
                uri = self.get_argument(call, "Path")
                if uri != "/" and uri != "":
                    self.request[self.lasthost]["uris"].append(uri)
                    self.request[self.lasthost]["curhandle"] = call["return"]
        elif call["api"] == "WinHttpGetProxyForUrl":
            url = self.get_argument(call, "Url")
            if url:
                for wlhost in domain_passlist:
                    if wlhost not in url:
                        self.urls.append(url)
        elif call["api"].startswith("InternetOpenUrl"):
            url = self.get_argument(call, "URL")
            if url:
                for wlhost in domain_passlist:
                    if wlhost not in url:
                        self.urls.append(url)

    def on_complete(self):
        ret = False
        # Parse to create self.data
        for host in self.request.keys():
            for uri in self.request[host]["uris"]:
                self.data.append({"url": "{}:{}/{}".format(host, self.request[host]["port"], uri)})

        for url in self.urls:
            self.data.append({"url": url})

        if len(self.data) > 0:
            ret = True

        return ret
