# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class Authenticode(Signature):
    name = "static_authenticode"
    description = "Presents an Authenticode digital signature"
    severity = 1
    weight = -1
    confidence = 30
    categories = ["static"]
    authors = ["Optiv"]
    minimum = "1.3"
    ttps = ["T1116"]  # MITRE v6
    ttps += ["T1553", "T1553.002"]  # MITRE v7,8

    def run(self):
        found_sig = False

        if "file" in self.results.get("target", {}) and "pe" in self.results["target"]["file"]:
            if self.results["target"]["file"]["pe"].get("digital_signers"):
                for sign in self.results["target"]["file"]["pe"]["digital_signers"]:
                    self.data.append(sign)
                    found_sig = True

        return found_sig


class InvalidAuthenticodeSignature(Signature):
    name = "invalid_authenticode_signature"
    description = "Authenticode signature is invalid"
    severity = 2
    confidence = 30
    categories = ["static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1116"]  # MITRE v6
    ttps += ["T1036"]  # MITRE v6,7,8
    ttps += ["T1036.001", "T1553", "T1553.002"]  # MITRE v7,8

    def run(self):
        ret = False
        if self.results.get("target", {}).get("file", {}).get("pe", {}).get("guest_signers"):
            signer = self.results["target"]["file"]["pe"]["guest_signers"]
            # digisig reports unsigned files and formats signtool cannot check as errors too
            not_signed = ("No signature found", "file format cannot be verified")
            error = signer.get("aux_error_desc") or ""
            if not signer.get("aux_valid") and error and not any(reason in error for reason in not_signed):
                self.data.append({"authenticode error": "%s" % (error)})
                ret = True

        return ret
