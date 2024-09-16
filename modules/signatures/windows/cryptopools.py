import re

from lib.cuckoo.common.abstracts import Signature

from data.cryptopools import pool_domains


class MINERS(Signature):
    name = "cryptopool_domains"
    description = "Connects to crypto currency mining pool"
    severity = 1
    categories = ["cryptomining"]
    authors = ["doomedraven", "bartblaze"]
    minimum = "1.2"
    ttps = ["T1496"]  # MITRE v6,7,8
    mbcs = ["OB0008", "B0018"]
    evented = True
    enabled = True

    filter_apinames = set(["GetAddrInfoW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.extra_domains = []

    def on_call(self, call, process):
        if call["api"] == "GetAddrInfoW":
            self.extra_domains.append(self.get_argument(call, "NodeName"))

    def on_complete(self):
        domains = [domain["domain"] for domain in self.results.get("network", {}).get("domains", [])]
        ret = False
        if not self.extra_domains:
            self.extra_domains = domains
        else:
            self.extra_domains += domains

        for domain in self.extra_domains:
            if domain and domain in pool_domains:
                self.malfamily = "crypto miner"
                self.results["malfamily"] = "crypto miner"
                self.results["malfamily_tag"] = "Behavior"
                self.data.append({"domain": domain})
                ret = True

            matches = [re.match(pool_domain, domain) for pool_domain in pool_domains]
            for match in matches:
                if match:
                    self.malfamily = "crypto miner"
                    self.results["malfamily"] = "crypto miner"
                    self.results["malfamily_tag"] = "Behavior"
                    self.data.append({"domain": match})
                    ret = True

            if self.check_executed_command(pattern=domain, regex=True):
                if domain:
                    self.malfamily = "crypto miner"
                    self.results["malfamily"] = "crypto miner"
                    self.results["malfamily_tag"] = "Behavior"
                    self.data.append({"domain": domain, "executed_command": True})
                    ret = True
        return ret
