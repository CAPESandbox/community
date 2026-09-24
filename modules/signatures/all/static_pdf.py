from lib.cuckoo.common.abstracts import Signature


class Static_PDF(Signature):
    name = "static_pdf"
    description = "The PDF file contains suspicious characteristics"
    severity = 2
    weight = 0
    categories = ["static"]
    authors = ["Kevin Ross", "KillerInstinct"]
    minimum = "1.3"
    ttps = ["T1204"]  # MITRE v6,7,8
    ttps += ["T1204.002"]  # MITRE v7,8

    def run(self):
        exploit = 0

        if "file" in self.results.get("target", {}) and "pdf" in self.results["target"]["file"]:
            if "PDF" in self.results.get("target", {})["file"].get("type", ""):
                if "Data After EOF" in self.results["target"]["file"]["pdf"]["Info"]:
                    if self.results["target"]["file"]["pdf"]["Info"]["Data After EOF"] != "0":
                        self.data.append({"data_after_eof": "PDF contains data after the declared end of file"})
                        self.weight += 1
                        self.severity = 3

                if "Keywords" in self.results["target"]["file"]["pdf"]:
                    if "/Page" in self.results["target"]["file"]["pdf"]["Keywords"]:
                        num_pages = self.results["target"]["file"]["pdf"]["Keywords"]["/Page"]
                        num_stream = self.results["target"]["file"]["pdf"]["Keywords"]["stream"]
                        num_obj = self.results["target"]["file"]["pdf"]["Keywords"]["obj"]
                        if num_pages > 10 and num_stream < 10 and num_obj < 35:
                            self.data.append(
                                {
                                    "content_anomaly": "PDF is a %s page document yet contains a low amount of objects and streams indicating a possible lack of content"
                                    % (num_pages)
                                }
                            )
                            self.weight += 1

                if "Keywords" in self.results["target"]["file"]["pdf"]:
                    if "/Page" in self.results["target"]["file"]["pdf"]["Keywords"]:
                        num_pages = self.results["target"]["file"]["pdf"]["Keywords"]["/Page"]
                        if num_pages == 1:
                            self.data.append({"single_page": "PDF contains one page. Many malicious PDFs only have one page."})
                            self.weight += 1

                if "Keywords" in self.results["target"]["file"]["pdf"]:
                    if (
                        "/JavaScript" in self.results["target"]["file"]["pdf"]["Keywords"]
                        or "/JS" in self.results["target"]["file"]["pdf"]["Keywords"]
                    ):
                        if (
                            self.results["target"]["file"]["pdf"]["Keywords"]["/JavaScript"] > 0
                            or self.results["target"]["file"]["pdf"]["Keywords"]["/JS"] > 0
                        ):
                            self.data.append({"javascript_object": "PDF contains JavaScript usage"})
                            self.ttps += ["T1064"]  # MITRE v6
                            self.ttps += ["T1059"]  # MITRE v6,7,8
                            self.ttps += ["T1059.007"]  # MITRE v7,8
                            self.mbcs += ["OB0009", "E1059"]
                            self.weight += 1

                if "Keywords" in self.results["target"]["file"]["pdf"]:
                    if "/XFA" in self.results["target"]["file"]["pdf"]["Keywords"]:
                        if self.results["target"]["file"]["pdf"]["Keywords"]["/XFA"] > 0:
                            self.data.append({"xfa_object": "Contains an XFA forms object"})
                            self.weight += 1

                if "Keywords" in self.results["target"]["file"]["pdf"]:
                    if "/EmbeddedFile" in self.results["target"]["file"]["pdf"]["Keywords"]:
                        if self.results["target"]["file"]["pdf"]["Keywords"]["/EmbeddedFile"] > 0:
                            self.data.append({"attachment": "PDF contains an attachment"})
                            self.mbcs += ["OB0009", "B0023"]
                            self.weight += 1

                if "Keywords" in self.results["target"]["file"]["pdf"]:
                    if (
                        "/OpenAction" in self.results["target"]["file"]["pdf"]["Keywords"]
                        or "/AA" in self.results["target"]["file"]["pdf"]["Keywords"]
                    ):
                        if (
                            self.results["target"]["file"]["pdf"]["Keywords"]["/OpenAction"] > 0
                            or self.results["target"]["file"]["pdf"]["Keywords"]["/AA"] > 0
                        ):
                            self.data.append({"open_action": "PDF contains an automatic open action"})
                            self.weight += 1

                # Specific Exploit Detection (this will be expanded upon & generic detections added too)
                if "Keywords" in self.results["target"]["file"]["pdf"]:
                    if "/Colors > 2^24" in self.results["target"]["file"]["pdf"]["Keywords"]:
                        if self.results["target"]["file"]["pdf"]["Keywords"]["/Colors > 2^24"] == 1:
                            self.data.append({"cve2009_3459": "Colors greater than 2 ^ 24 heap overflow exploit"})
                            exploit += 1

            if exploit > 0:
                self.ttps += ["T1203"]  # MITRE v6,7,8
                self.mbcs += ["OB0009", "E1203"]
                self.description += " and contains possible exploit code."
                self.severity = 3
                self.weight += 1

        if self.weight:
            if self.weight >= 3:
                self.severity = 3
            return True

        return False
