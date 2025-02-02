from lib.cuckoo.common.abstracts import Signature


class PersistenceViaAutodialDLLRegistry(Signature):
    name = "persistence_via_autodial_dll_registry"
    description = "Attempt to load malicious DLL when Winsock library (ws2_32.dll) is loaded"
    severity = 3
    categories = ["persistence", "bypass"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1112", "T1547"]
    references = [
        "https://www.hexacorn.com/blog/2015/01/13/beyond-good-ol-run-key-part-24/",
        "https://decoded.avast.io/luigicamastra/operation-dragon-castling-apt-group-targeting-betting-companies/",
    ]

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False

    def on_call(self, call, _):
        if call["api"] in ("RegSetValueExA", "RegSetValueExW"):
            regKeyPath = self.get_argument(call, "FullName").lower()
            buf = self.get_argument(call, "Buffer")

            if "\\services\\winsock2\\parameters\\autodialdll" in regKeyPath and not "rasadhlp.dll" in buf:
                self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False
