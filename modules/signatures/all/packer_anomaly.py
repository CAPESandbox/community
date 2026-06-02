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


lass PEDeepEntrypoint(Signature):
    name = "pe_deep_entrypoint"
    description = "The PE entry point is located unusually far into its section, indicative of an appended packer stub"
    severity = 2
    confidence = 50
    categories = ["packer", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1027"]
    mbcs = ["OB0013", "B0002"]
 
    def run(self):
        pe = self.results.get("target", {}).get("file", {}).get("pe", {})
        if not pe:
            return False
 
        # Skip .NET binaries — the CLR bootstrap EP is always at the tail of .text
        dirents = pe.get("dirents", [])
        for d in dirents:
            if d.get("name") == "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR":
                try:
                    if int(d.get("virtual_address") or "0x0", 16) != 0:
                        return False
                except (ValueError, TypeError):
                    pass
 
        try:
            ep_rva = int(pe.get("entrypoint", "0x0"), 16)
        except (ValueError, TypeError):
            return False
 
        if ep_rva == 0:
            return False
 
        for section in pe.get("sections", []):
            try:
                va    = int(section["virtual_address"], 16)
                vsize = int(section["virtual_size"], 16)
                rsize = int(section["size_of_data"], 16)
            except (ValueError, TypeError, KeyError):
                continue
 
            span = max(vsize, rsize)
            if span == 0:
                continue
 
            if va <= ep_rva < va + span:
                ep_offset = ep_rva - va
                ep_pct = ep_offset / span
 
                if ep_pct >= 0.80:
                    self.data.append({
                        "section": section.get("name", "?"),
                        "ep_rva": hex(ep_rva),
                        "ep_offset": hex(ep_offset),
                        "section_span": hex(span),
                        "percent_into_section": f"{ep_pct:.0%}",
                    })
                    self.severity = 3
                    return True
 
                if ep_pct >= 0.60:
                    self.data.append({
                        "section": section.get("name", "?"),
                        "ep_rva": hex(ep_rva),
                        "ep_offset": hex(ep_offset),
                        "section_span": hex(span),
                        "percent_into_section": f"{ep_pct:.0%}",
                    })
                    return True
 
        return False


class PEEntrypointOutsideSections(Signature):
    name = "pe_entrypoint_outside_sections"
    description = "The PE entry point falls outside all declared sections, indicating manual stub injection or severe header corruption"
    severity = 2
    confidence = 80
    categories = ["packer", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1027"]
    mbcs = ["OB0013", "B0002"]

    def run(self):
        pe = self.results.get("target", {}).get("file", {}).get("pe", {})
        if not pe:
            return False

        try:
            ep_rva = int(pe.get("entrypoint", "0x0"), 16)
        except (ValueError, TypeError):
            return False

        if ep_rva == 0:
            return False

        for section in pe.get("sections", []):
            try:
                va    = int(section["virtual_address"], 16)
                vsize = int(section["virtual_size"], 16)
                rsize = int(section["size_of_data"], 16)
            except (ValueError, TypeError, KeyError):
                continue
            if va <= ep_rva < va + max(vsize, rsize):
                return False

        self.data.append({"ep_rva": hex(ep_rva)})
        return True


                # EP is in section but not deep enough — no need to keep searching
                return False

        return False


class PEEntrypointInNonCodeSection(Signature):
    name = "pe_entrypoint_in_non_code_section"
    description = "The PE entry point is located in a non-executable section, consistent with a packer stub in a non-standard section"
    severity = 2
    confidence = 70
    categories = ["packer", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1027"]
    mbcs = ["OB0013", "B0002"]

    def run(self):
        pe = self.results.get("target", {}).get("file", {}).get("pe", {})
        if not pe:
            return False

        try:
            ep_rva = int(pe.get("entrypoint", "0x0"), 16)
        except (ValueError, TypeError):
            return False

        if ep_rva == 0:
            return False

        for section in pe.get("sections", []):
            try:
                va    = int(section["virtual_address"], 16)
                vsize = int(section["virtual_size"], 16)
                rsize = int(section["size_of_data"], 16)
                chars = int(section["characteristics_raw"], 16)
            except (ValueError, TypeError, KeyError):
                continue

            span = max(vsize, rsize)
            if not (va <= ep_rva < va + span):
                continue

            # IMAGE_SCN_MEM_EXECUTE = 0x20000000
            is_executable = bool(chars & 0x20000000)
            if not is_executable:
                self.data.append({
                    "section": section.get("name", "?"),
                    "ep_rva": hex(ep_rva),
                    "characteristics": section.get("characteristics", "?"),
                })
                return True

        return False


class PEWritableExecutableSection(Signature):
    name = "pe_writable_executable_section"
    description = "A PE section has both write and execute permissions (W+X), indicating a self-modifying stub or in-place unpacker"
    severity = 3
    confidence = 70
    categories = ["packer", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1027"]
    mbcs = ["OB0013", "B0002"]

    def run(self):
        pe = self.results.get("target", {}).get("file", {}).get("pe", {})
        if not pe:
            return False

        ret = False
        for section in pe.get("sections", []):
            try:
                chars = int(section["characteristics_raw"], 16)
            except (ValueError, TypeError, KeyError):
                continue

            is_exec  = bool(chars & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
            is_write = bool(chars & 0x80000000)  # IMAGE_SCN_MEM_WRITE
            if is_exec and is_write:
                self.data.append({
                    "section": section.get("name", "?"),
                    "characteristics": section.get("characteristics", "?"),
                })
                ret = True

        return ret


class PESectionVsizeRsizeAnomaly(Signature):
    name = "pe_section_vsize_rsize_anomaly"
    description = "A PE section has a virtual size significantly larger than its raw size, consistent with an in-place unpacker expanding into virtual memory at runtime"
    severity = 2
    confidence = 50
    categories = ["packer", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1027"]
    mbcs = ["OB0013", "B0002"]

    def run(self):
        pe = self.results.get("target", {}).get("file", {}).get("pe", {})
        if not pe:
            return False

        ret = False
        for section in pe.get("sections", []):
            try:
                vsize = int(section["virtual_size"], 16)
                rsize = int(section["size_of_data"], 16)
            except (ValueError, TypeError, KeyError):
                continue

            if rsize == 0 or vsize == 0:
                continue

            # vsize >> rsize: section expands significantly in memory.
            # 4x threshold with a minimum absolute size avoids flagging
            # small BSS-style sections which legitimately have large vsize.
            if vsize > rsize * 4 and vsize > 0x10000:
                self.data.append({
                    "section": section.get("name", "?"),
                    "virtual_size": hex(vsize),
                    "raw_size": hex(rsize),
                    "expansion_ratio": f"{vsize // rsize}x",
                })
                ret = True

        return ret


class PETLSCallbacks(Signature):
    name = "pe_tls_callbacks"
    description = "The PE file contains TLS callbacks which execute before the entry point and before debugger attachment, commonly used by packers for anti-analysis or pre-EP decryption"
    severity = 2
    confidence = 50
    categories = ["packer", "anti-debug", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1027", "T1055"]
    mbcs = ["OB0013", "B0002"]

    def run(self):
        pe = self.results.get("target", {}).get("file", {}).get("pe", {})
        if not pe:
            return False

        dirents = pe.get("dirents", [])
        tls_dirent = next(
            (d for d in dirents if d.get("name") == "IMAGE_DIRECTORY_ENTRY_TLS"),
            None
        )
        if not tls_dirent:
            return False

        try:
            tls_va   = int(tls_dirent["virtual_address"], 16)
            tls_size = int(tls_dirent["size"], 16)
        except (ValueError, TypeError, KeyError):
            return False

        if tls_va == 0 or tls_size == 0:
            return False

        self.data.append({
            "tls_directory_va": hex(tls_va),
            "tls_directory_size": hex(tls_size),
        })
        return True


class PEExportsInExecutable(Signature):
    name = "pe_exports_in_executable"
    description = "A PE executable (not DLL) exports symbols, which is unusual and may indicate a dual-mode loader or packer that exposes its own entry points"
    severity = 2
    confidence = 50
    categories = ["packer", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1027"]
    mbcs = ["OB0013"]

    def run(self):
        pe = self.results.get("target", {}).get("file", {}).get("pe", {})
        if not pe:
            return False

        # Only flag EXEs (not DLLs)
        machine = pe.get("machine_type", "")
        target_type = self.results.get("target", {}).get("file", {}).get("type", "")
        if "DLL" in target_type.upper():
            return False

        exports = pe.get("exports", [])
        if not exports:
            return False

        self.data.append({
            "export_count": len(exports),
            "exports": [e.get("name") or f"ordinal_{e.get('ordinal')}" for e in exports[:10]],
        })
        return True


class PESectionVsizeRsizeAnomaly(Signature):
    name = "pe_section_vsize_rsize_anomaly"
    description = "A PE section has a virtual size significantly larger than its raw size, consistent with packed code expanding into virtual memory at runtime"
    severity = 2
    confidence = 50
    categories = ["packer", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1027"]
    mbcs = ["OB0013", "B0002"]

    def run(self):
        pe = self.results.get("target", {}).get("file", {}).get("pe", {})
        if not pe:
            return False

        ret = False
        for section in pe.get("sections", []):
            try:
                vsize = int(section["virtual_size"], 16)
                rsize = int(section["size_of_data"], 16)
            except (ValueError, TypeError, KeyError):
                continue

            if rsize == 0 or vsize == 0:
                continue

            # vsize >> rsize: section expands significantly in memory.
            # 4x threshold with a minimum absolute size avoids flagging
            # small BSS-style sections which legitimately have large vsize.
            if vsize > rsize * 4 and vsize > 0x10000:
                self.data.append({
                    "section": section.get("name", "?"),
                    "virtual_size": hex(vsize),
                    "raw_size": hex(rsize),
                    "expansion_ratio": f"{vsize // rsize}x",
                })
                ret = True

        return ret
