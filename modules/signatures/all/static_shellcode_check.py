# Copyright (C) 2026 Kevin Ross
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


def _iter_shellcode_files(results):
    # the submitted file (shellcode / shellcode_x64 packages) and CAPE's extracted payloads
    # Prefer CAPE payloads first so runtime process/PID/injection context is retained on duplicate SHA256s.
    files = [("CAPE payload", payload) for payload in (results.get("CAPE") or {}).get("payloads") or []]
    target = (results.get("target") or {}).get("file") or {}
    if target.get("static_shellcode_check"):
        files.append(("submitted file", target))

    seen = set()
    for source, payload in files:
        if not isinstance(payload, dict):
            continue
        check = payload.get("static_shellcode_check") or {}
        sha256 = payload.get("sha256")
        if not check or (sha256 and sha256 in seen):
            continue  # a dump of the submitted shellcode is reported once
        if sha256:
            seen.add(sha256)
        yield source, payload, check


def _build_shellcode_entry(source, payload, check):
    entry = {"source": source}
    if payload.get("process_name"):
        entry["process"] = payload["process_name"]
    if payload.get("pid") not in (None, ""):
        entry["pid"] = payload["pid"]
    if payload.get("cape_type"):
        entry["cape_type"] = payload["cape_type"]
    if payload.get("sha256"):
        entry["sha256"] = payload["sha256"]
    if check.get("arch"):
        entry["arch"] = check["arch"]
    if check.get("tags"):
        entry["indicators"] = ", ".join(check["tags"])
    if payload.get("target_process"):
        entry["target"] = f"{payload['target_process']} ({payload.get('target_pid', '')})"
    if payload.get("virtual_address"):
        entry["virtual_address"] = payload["virtual_address"]
    if check.get("capabilities"):
        entry["capabilities"] = ", ".join(check["capabilities"])
    return entry


class CAPEShellcodeConfirmed(Signature):
    name = "cape_shellcode_confirmed"
    description = "CAPE extracted payload statically confirmed as shellcode"
    severity = 3
    confidence = 90
    categories = ["shellcode", "injection", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1055", "T1620"]

    def run(self):
        ret = False
        for source, payload, check in _iter_shellcode_files(self.results):
            if check.get("verdict") != "shellcode":
                continue
            self.data.append(_build_shellcode_entry(source, payload, check))
            ret = True
        return ret


class CAPEShellcodeLikely(Signature):
    name = "cape_shellcode_likely"
    description = "CAPE extracted a payload with possible shellcode traits (unconfirmed)"
    severity = 2
    confidence = 50
    categories = ["shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"

    def run(self):
        ret = False
        for source, payload, check in _iter_shellcode_files(self.results):
            if check.get("verdict") != "likely":
                continue
            self.data.append(_build_shellcode_entry(source, payload, check))
            ret = True
        return ret


class CAPEShellcodePELoader(Signature):
    name = "cape_shellcode_pe_loader"
    description = "CAPE extracted shellcode that maps or carries a PE image"
    severity = 3
    confidence = 80
    categories = ["shellcode", "injection"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1620"]

    def run(self):
        ret = False
        for source, payload, check in _iter_shellcode_files(self.results):
            if check.get("verdict") not in ("shellcode", "likely"):
                continue
            tags = set(check.get("tags", []))
            hidden = [r for r in check.get("regions") or [] if r.get("result_type") == "pe"]
            if not (tags & {"reflective_pe_loader", "executable_pe_header", "staged_pe"} or hidden):
                continue
            entry = _build_shellcode_entry(source, payload, check)
            pes = check.get("embedded_pe") or []
            if pes:
                entry["embedded_pe"] = ", ".join(f"{p['offset']} {p['arch']} {'DLL' if p['dll'] else 'EXE'}" for p in pes)
            if hidden:
                # decoded by a linked decoder, or carried by a known generator (Donut module, sRDI DLL)
                entry["carried_pe"] = ", ".join(
                    (f"{r['start']}-{r['end']}" if r.get("end") else str(r["start"]))
                    + f" {r['result']}"
                    + (f" ({r['framework']})" if r.get("framework") else "")
                    for r in hidden
                )
            self.data.append(entry)
            ret = True
        return ret


class CAPEShellcodeTechnique(Signature):
    name = "cape_shellcode_evasive_technique"
    description = "CAPE extracted shellcode that uses evasion techniques"
    severity = 3
    confidence = 60
    categories = ["shellcode", "evasion", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1106"]

    TECHNIQUES = (
        "direct_syscall",
        "indirect_syscall",
        "syscall_stub_scan",
        "heavens_gate",
        "wow64_transition",
        "amsi_etw_patch",
        "amsi_context_patch",
        "pe_header_wipe",
        "kernel_token_steal",
        "ntdll_copy",
    )

    def run(self):
        ret = False
        for source, payload, check in _iter_shellcode_files(self.results):
            # 'image' covers a copy of ntdll's syscall stubs (unhooking) found on its own
            if check.get("verdict") not in ("shellcode", "likely", "image"):
                continue
            hits = [t for t in check.get("tags", []) if t in self.TECHNIQUES]
            if check.get("verdict") == "image":
                hits = [t for t in hits if t == "ntdll_copy"]
            if not hits:
                continue
            entry = _build_shellcode_entry(source, payload, check)
            entry["technique"] = ", ".join(hits)
            self.data.append(entry)
            ret = True
        return ret


class CAPEShellcodeNetworkIOC(Signature):
    name = "cape_shellcode_network_iocs"
    description = "CAPE extracted shellcode carries network indicators"
    severity = 2
    confidence = 50
    categories = ["shellcode", "network", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1071"]

    NETWORK_IOCS = ("urls", "network", "ips", "domains", "user_agents", "pipes")

    def run(self):
        ret = False
        for source, payload, check in _iter_shellcode_files(self.results):
            if check.get("verdict") not in ("shellcode", "likely"):
                continue
            iocs = check.get("iocs") or {}
            found = {k: iocs[k] for k in self.NETWORK_IOCS if iocs.get(k)}
            if not found:
                continue
            entry = _build_shellcode_entry(source, payload, check)
            for k, v in found.items():
                entry[k] = ", ".join(v[:10])
            self.data.append(entry)
            ret = True
        return ret


class CAPEShellcodeFramework(Signature):
    name = "cape_shellcode_framework"
    description = "CAPE extracted shellcode produced by a known framework"
    severity = 3
    confidence = 90
    categories = ["shellcode", "injection", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1620"]

    def run(self):
        ret = False
        for source, payload, check in _iter_shellcode_files(self.results):
            if check.get("verdict") != "shellcode":
                continue
            for fw in check.get("frameworks") or []:
                if fw.get("confidence") != "identified":
                    continue
                entry = _build_shellcode_entry(source, payload, check)
                entry["framework"] = fw["name"]
                for k, v in (fw.get("details") or {}).items():
                    if v not in (None, ""):
                        entry[k if k not in entry else f"framework_{k}"] = v
                self.data.append(entry)
                ret = True
        return ret


class CAPEShellcodeEncoder(Signature):
    name = "cape_shellcode_encoder"
    description = "CAPE extracted shellcode containing a known encoder"
    severity = 2
    confidence = 80
    categories = ["shellcode", "obfuscation", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1027"]

    def run(self):
        ret = False
        for source, payload, check in _iter_shellcode_files(self.results):
            if check.get("verdict") != "shellcode":
                continue
            enc = check.get("encoder")
            if not enc:
                continue
            entry = _build_shellcode_entry(source, payload, check)
            entry["encoder"] = enc["name"]
            if enc.get("payload"):
                entry["decodes_to"] = enc["payload"]
            self.data.append(entry)
            ret = True
        return ret
