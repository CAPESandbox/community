from lib.cuckoo.common.abstracts import Signature


class RansomwareSTOPDJVU(Signature):
    name = "ransomware_stopdjvu"
    description = "Exhibits behavior characteristic of STOP/DJVU ransomware"
    weight = 3
    severity = 3
    categories = ["ransomware"]
    families = ["STOP"]
    authors = ["@para0x0dise"]
    minimum = "1.3"
    evented = True
    ttps = ["T1486"]

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands")
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if all([pattern in lower for pattern in ("--admin", "isnottask", "isnotautostart")]):
                return True
        return False
