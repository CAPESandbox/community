# Copyright (C) 2010-2015 Cuckoo Foundation, 2019 Kevin Ross
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature


class PackerUnknownPESectionName(Signature):
    name = "packer_unknown_pe_section_name"
    description = "The binary contains an unknown PE section name indicative of packing"
    severity = 2
    categories = ["packer"]
    authors = ["Cuckoo Technologies", "Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1045"]  # MITRE v6
    ttps += ["T1027"]  # MITRE v6,7,8
    ttps += ["T1027.002"]  # MITRE v7,8
    mbcs = ["OB0001", "OB0002", "OB0006", "F0001"]

    def run(self):
        ret = False
        knownsections = [
            ".aspack",
            ".bss",
            ".crt",
            ".data",
            ".debug",
            ".edata",
            ".eh_fram",
            ".enigma",
            ".gdata",
            ".idata",
            ".mpress",
            ".nate",
            ".ndata",
            ".pdata",
            ".rdata",
            ".reloc",
            ".rsrc",
            ".shared",
            ".text",
            ".themida",
            ".titan",
            ".tls",
            ".upx",
            ".vmp",
            ".xdata",
        ]

        target = self.results.get("target", {})
        if target.get("category") in ("file", "static") and target.get("file"):
            pe = self.results["target"]["file"].get("pe", [])
            if pe:
                for section in pe["sections"]:
                    if section["name"].lower() not in knownsections:
                        ret = True
                        self.data.append({"unknown section": section})

        return ret


class PEDeepEntrypoint(Signature):
    name = "pe_deep_entrypoint"
    description = "The PE entry point is located unusually far into section, indicative of an appended packer stub that jumps to the original entry point (OEP)"
    severity = 2
    confidence = 100
    categories = ["static", "packer", "evasion", "anomaly"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1027"]
    mbcs = ["E1027"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.depth_threshold_percentage = 80.0

    @staticmethod
    def _parse_hex_or_int(value, default=0):
        """Safely parse a value that may be a hex string, decimal string, or int."""
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 16) if value.startswith("0x") else int(value)
            except (ValueError, TypeError):
                return default
        return default

    def run(self):
        target = self.results.get("target", {})
        if target.get("category") not in ("file", "static") or not target.get("file"):
            return False

        pe = target["file"].get("pe", {})
        if not pe:
            return False

        ep_raw = pe.get("entrypoint")
        if ep_raw is None:
            return False

        ep_val = self._parse_hex_or_int(ep_raw)
        if ep_val == 0:
            return False

        sections = pe.get("sections", [])
        if not sections:
            return False

        for sec in sections:
            vaddr = self._parse_hex_or_int(sec.get("virtual_address", 0))
            vsize = self._parse_hex_or_int(sec.get("virtual_size", 0))

            if vsize == 0:
                continue
            if vaddr <= ep_val < (vaddr + vsize):
                offset = ep_val - vaddr
                percentage = (offset / float(vsize)) * 100.0

                if percentage >= self.depth_threshold_percentage:
                    sec_name = sec.get("name", "unknown")
                    try:
                        entropy = float(sec.get("entropy", 0.0))
                    except (ValueError, TypeError):
                        entropy = 0.0
                    if percentage >= 95.0 or entropy >= 7.0:
                        self.severity = 3
                    dynamic_desc = (
                        f"The PE entry point (0x{ep_val:x}) is located {percentage:.1f}% "
                        f"deep into the '{sec_name}' section. Normal compilers place the EP "
                        f"near the beginning. This strongly indicates an appended packer stub "
                        f"or shellcode."
                    )
                    self.data.append(
                        {
                            "anomaly_description": dynamic_desc,
                            "entry_point": hex(ep_val),
                            "section_name": sec_name,
                            "section_virtual_address": hex(vaddr),
                            "section_virtual_size": hex(vsize),
                            "offset_bytes": hex(offset),
                            "depth_percentage": round(percentage, 2),
                            "section_entropy": round(entropy, 2),
                        }
                    )

                    return True

                # EP is in section but not deep enough — no need to keep searching
                return False

        return False
