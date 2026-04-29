# Copyright (C) 2026
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

"""BYOD (Bring-Your-Own-Driver) detection processing module.

Sources:
  - data/loldrivers.json — community feed of known vulnerable/malicious drivers
                          (download with utils/fetch_loldrivers.py)
  - data/security_tools.json — exe basename → tool/vendor/category mapping
  - storage/analyses/<task>/evtx/evtx.zip — Sysmon EID 1/5/6/11, System EID 7045
  - results.behavior — process tree + executed_commands
  - results.target.file — sample SHA256 / filename for sample-under-test discriminator

Output: results["loldrivers"] = {
    "drivers_loaded":   [...],   # all DriverLoaded events with metadata
    "matches":          [...],   # tiered LOLDrivers matches (sha256 / signer+name / name)
    "novel_candidates": [...],   # novel-driver heuristic flags
    "exploitation":     [...],   # post-load exploitation correlation
    "service_installs": [...],   # System EID 7045 driver-service installs
    "summary":          {...},   # counts
}
"""

import json
import logging
import os
import re
import tempfile
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from lib.cuckoo.common.abstracts import CUCKOO_ROOT, Processing

log = logging.getLogger(__name__)

# Module-level cache for the LOLDrivers + security_tools feeds (loaded once per worker).
_LOLD_CACHE = None
_TOOLS_CACHE = None

LOLDRIVERS_PATH = os.path.join(CUCKOO_ROOT, "data", "loldrivers.json")
SECURITY_TOOLS_PATH = os.path.join(CUCKOO_ROOT, "data", "security_tools.json")

# Driver paths considered "system" (not novel).
SYSTEM_DRIVER_PREFIXES = (
    "c:\\windows\\system32\\drivers\\",
    "c:\\windows\\syswow64\\drivers\\",
    "c:\\windows\\system32\\driverstore\\",
    "c:\\windows\\winsxs\\",
    "\\systemroot\\system32\\drivers\\",
    "\\??\\c:\\windows\\system32\\drivers\\",
)

# Suspicious driver paths.
SUSPICIOUS_DRIVER_PATH_HINTS = (
    "\\temp\\",
    "\\appdata\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\windows\\temp\\",
    "\\downloads\\",
    "\\desktop\\",
)

# Window for post-load exploitation correlation.
POST_LOAD_WINDOW_SEC = 120

EXPLOITATION_KILL_CATEGORIES = {"EDR", "AV"}
ANTI_ANALYSIS_KILL_CATEGORIES = {
    "NetworkAnalysis",
    "ProcessInspection",
    "ReverseEngineering",
    "Forensics",
    "Sysinternals",
    "Sandbox",
}


def _load_loldrivers():
    global _LOLD_CACHE
    if _LOLD_CACHE is not None:
        return _LOLD_CACHE
    if not os.path.exists(LOLDRIVERS_PATH):
        log.warning(
            "loldrivers feed not found at %s — run utils/fetch_loldrivers.py to download. BYOD detection disabled.",
            LOLDRIVERS_PATH,
        )
        _LOLD_CACHE = {"by_sha256": {}, "by_signer_name": {}, "by_name": {}, "entries": 0}
        return _LOLD_CACHE
    try:
        with open(LOLDRIVERS_PATH) as f:
            raw = json.load(f)
        if not isinstance(raw, list):
            raise ValueError("expected JSON array, got %s" % type(raw).__name__)
    except Exception as e:
        log.error("failed loading loldrivers feed: %s", e)
        _LOLD_CACHE = {"by_sha256": {}, "by_signer_name": {}, "by_name": {}, "entries": 0}
        return _LOLD_CACHE

    by_sha256 = {}
    by_signer_name = {}
    by_name = defaultdict(list)
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        category = entry.get("Category", "")
        eid = entry.get("Id", "")
        for sample in entry.get("KnownVulnerableSamples") or []:
            if not isinstance(sample, dict):
                continue
            sha = (sample.get("SHA256") or "").lower()
            fname = (sample.get("Filename") or "").lower()
            signers = []
            for sig in sample.get("Signatures") or []:
                if not isinstance(sig, dict):
                    continue
                for cert in sig.get("Certificates") or []:
                    if not isinstance(cert, dict):
                        continue
                    sub = cert.get("Subject") or ""
                    m = re.search(r"CN=([^,]+)", sub)
                    if m:
                        signers.append(m.group(1).strip().lower())
            base = {
                "id": eid,
                "category": category,
                "filename": fname,
                "sha256": sha,
                "signers": signers,
            }
            if sha:
                by_sha256[sha] = base
            if fname:
                by_name[fname].append(base)
                for signer in signers:
                    by_signer_name[(signer, fname)] = base
    _LOLD_CACHE = {
        "by_sha256": by_sha256,
        "by_signer_name": by_signer_name,
        "by_name": dict(by_name),
        "entries": len(raw),
    }
    log.info(
        "loldrivers loaded: %d entries, %d sha256, %d (signer,name), %d names",
        _LOLD_CACHE["entries"],
        len(by_sha256),
        len(by_signer_name),
        len(by_name),
    )
    return _LOLD_CACHE


def _load_tools():
    global _TOOLS_CACHE
    if _TOOLS_CACHE is not None:
        return _TOOLS_CACHE
    if not os.path.exists(SECURITY_TOOLS_PATH):
        _TOOLS_CACHE = {}
        return _TOOLS_CACHE
    try:
        with open(SECURITY_TOOLS_PATH) as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            raise ValueError("expected JSON object with 'tools' key, got %s" % type(raw).__name__)
        tools = raw.get("tools") or {}
        if not isinstance(tools, dict):
            raise ValueError("'tools' must be a JSON object, got %s" % type(tools).__name__)
        # Reject entries that aren't well-formed.
        _TOOLS_CACHE = {
            k: v
            for k, v in tools.items()
            if isinstance(k, str) and isinstance(v, dict) and "category" in v
        }
    except Exception as e:
        log.error("failed loading security_tools feed: %s", e)
        _TOOLS_CACHE = {}
    return _TOOLS_CACHE


def _is_system_path(path):
    if not path:
        return False
    p = path.lower().replace("/", "\\")
    return any(p.startswith(prefix) for prefix in SYSTEM_DRIVER_PREFIXES)


def _is_suspicious_path(path):
    if not path:
        return False
    p = path.lower()
    return any(h in p for h in SUSPICIOUS_DRIVER_PATH_HINTS)


def _service_create_cmdline_for(driver_path, driver_basename, executed_commands):
    """Return True if executed_commands contains a kernel-driver service create/start
    that targets this driver. Matches `sc(.exe)? create ...` or `sc(.exe)? start ...`
    when the cmdline references the driver's full path or its basename. We don't
    require type=kernel because some loaders omit it (sc inherits the type from
    binPath= ".sys" via SCM defaults in some Windows versions), but we do require
    the literal verb (create / start) to keep the gate tight."""
    if not executed_commands:
        return False
    bn = (driver_basename or "").lower()
    dp = (driver_path or "").lower()
    if not (bn or dp):
        return False
    for cmd in executed_commands:
        low = cmd.lower()
        if "sc " not in low and "sc.exe" not in low:
            continue
        if "create" not in low and "start" not in low:
            continue
        if (dp and dp in low) or (bn and bn in low):
            return True
    return False


def _basename(path):
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _filetime_to_dt(s):
    """Parse Sysmon UtcTime (e.g. '2026-04-28 16:57:01.123') → aware UTC datetime."""
    if not s:
        return None
    s = s.strip().rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
    except Exception:
        return None


_EID_RE = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
_TIME_RE = re.compile(r'<TimeCreated[^/]*SystemTime="([^"]+)"')
_DATA_RE = re.compile(r'<Data Name="([^"]+)">([^<]*)</Data>')


def _parse_evtx_records(evtx_path, wanted_eids):
    """Yield {eid, time, data: {name: value}} for records matching wanted_eids."""
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        log.warning("python-evtx not available — BYOD sysmon parsing skipped")
        return
    try:
        with Evtx(evtx_path) as log_:
            for record in log_.records():
                try:
                    xml = record.xml()
                except Exception:
                    continue
                m = _EID_RE.search(xml)
                if not m:
                    continue
                eid = m.group(1)
                if eid not in wanted_eids:
                    continue
                tm = _TIME_RE.search(xml)
                time_str = None
                if tm:
                    raw = tm.group(1)
                    time_str = raw.replace("T", " ").rstrip("Z")
                data = {k: v for k, v in _DATA_RE.findall(xml)}
                yield {"eid": eid, "time": time_str, "data": data}
    except Exception as e:
        log.warning("evtx parse failed for %s: %s", evtx_path, e)


def _extract_evtx(zip_path, name_filters, target_dir, max_size=5 * 1024 * 1024 * 1024):
    """Extract evtx files matching any of name_filters into target_dir; return list of paths."""
    paths = []
    if not os.path.exists(zip_path):
        return paths
    total_extracted = 0
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                if any(f.lower() in info.filename.lower() for f in name_filters):
                    total_extracted += info.file_size
                    if total_extracted > max_size:
                        log.warning("evtx zip extraction exceeded %d bytes, aborting", max_size)
                        break
                    extracted_path = zf.extract(info, target_dir)
                    paths.append(extracted_path)
    except Exception as e:
        log.warning("zip extract failed for %s: %s", zip_path, e)
    return paths


class LolDrivers(Processing):
    """BYOD detection: tiered driver match + novel-driver heuristic + exploitation correlation."""

    order = 11  # after sysmon (10), before signatures
    key = "loldrivers"

    def _build_pid_name_map(self):
        m = {}
        procs = (self.results.get("behavior") or {}).get("processes") or []
        for p in procs:
            pid = p.get("process_id")
            name = (p.get("process_name") or "").lower()
            if pid and name:
                m[int(pid)] = name
        return m

    def _is_sample_being_analyzed(self, driver_path):
        """Return True if the driver file IS the sample under test."""
        if not driver_path:
            return False
        target = (self.results.get("target") or {}).get("file") or {}
        sample_name = (target.get("name") or "").lower()
        bn = _basename(driver_path)
        if sample_name and bn == sample_name:
            return True
        return False

    def _classify_driver(self, driver):
        feed = _load_loldrivers()
        sha = (driver.get("sha256") or "").lower()
        name = _basename(driver.get("path"))
        signer = (driver.get("signer") or "").lower()

        if sha and sha in feed["by_sha256"]:
            entry = feed["by_sha256"][sha]
            return {
                "tier": "definitive_sha256",
                "severity": "critical",
                "loldrivers_id": entry["id"],
                "category": entry["category"],
                "matched_filename": entry.get("filename"),
                "reason": "SHA256 hash matches LOLDrivers entry %s" % entry["id"],
            }
        if signer and name:
            entry = feed["by_signer_name"].get((signer, name))
            if entry:
                return {
                    "tier": "high_signer_name",
                    "severity": "high",
                    "loldrivers_id": entry["id"],
                    "category": entry["category"],
                    "matched_filename": entry.get("filename"),
                    "reason": "signer '%s' + filename '%s' match LOLDrivers %s" % (signer, name, entry["id"]),
                }
        if name and name in feed["by_name"]:
            entries = feed["by_name"][name]
            return {
                "tier": "medium_name",
                "severity": "medium",
                "loldrivers_id": entries[0]["id"],
                "category": entries[0]["category"],
                "matched_filename": entries[0].get("filename"),
                "matches_count": len(entries),
                "reason": "filename '%s' present in LOLDrivers (%d entries) — name collision possible" % (name, len(entries)),
            }
        return None

    def _classify_novel(self, driver, service_installs):
        path = driver.get("path") or ""
        name = _basename(path)
        signals = []
        if not _is_system_path(path) and _is_suspicious_path(path):
            signals.append("non_system_path:%s" % path)
        if not driver.get("signed", False):
            signals.append("unsigned")
        elif (driver.get("signature_status") or "").lower() not in ("valid", "trusted", ""):
            signals.append("invalid_signature:%s" % driver.get("signature_status"))
        if driver.get("created_by_sample"):
            signals.append("dropped_by_sample:pid=%s" % driver.get("creator_pid"))
        for svc in service_installs:
            if svc.get("image_path", "").lower() == path.lower() or _basename(svc.get("image_path", "")) == name:
                signals.append("service_install:%s" % svc.get("service_name"))
                break
        return signals

    def _correlate_eid5_kills(self, driver_load_time, sysmon_records):
        """Per-driver EID 5 correlation: process-terminate events within
        POST_LOAD_WINDOW_SEC of the driver load whose image basename matches a known
        security tool. Time-bounded because each EID 5 record carries its own timestamp."""
        if not driver_load_time:
            return []
        t0 = _filetime_to_dt(driver_load_time)
        if not t0:
            return []
        window_end = t0 + timedelta(seconds=POST_LOAD_WINDOW_SEC)

        tools = _load_tools()
        findings = []
        for rec in sysmon_records:
            if rec["eid"] != "5":
                continue
            t = _filetime_to_dt(rec.get("time"))
            if not t or not (t0 <= t <= window_end):
                continue
            img = rec["data"].get("Image", "")
            bn = _basename(img)
            info = tools.get(bn)
            if info and info["category"] in (EXPLOITATION_KILL_CATEGORIES | ANTI_ANALYSIS_KILL_CATEGORIES):
                sev = "high" if info["category"] in EXPLOITATION_KILL_CATEGORIES else "medium"
                findings.append(
                    {
                        "kind": "process_terminated_security_tool",
                        "severity": sev,
                        "tool": info["tool"],
                        "vendor": info["vendor"],
                        "category": info["category"],
                        "image": img,
                        "time": rec.get("time"),
                    }
                )
        return findings

    def _correlate_kill_cmdlines(self, executed_commands):
        """Analysis-global cmdline correlation: kill verbs (taskkill / Stop-Process /
        wmic delete) targeting a known security tool in any executed_command captured
        during the analysis. Run once per analysis (not per driver) — Sysmon EID 5 only
        fires when the *target* was actually running and Sysmon observed the termination,
        and many sandbox VMs ship without Defender/EDR enabled, so the EID 5 path misses
        *attempted* kills. We accept any matching cmdline within the analysis because:
        (a) BYOD analyses are short and bounded by the timeout, (b) the kill verbs are
        highly specific, and (c) the caller only attaches the result when at least one
        driver actually loaded."""
        if not executed_commands:
            return []
        tools = _load_tools()
        findings = []
        seen = set()
        for cmd in executed_commands:
            low = cmd.lower()
            kill_keyword = ("taskkill" in low) or ("stop-process" in low) or ("wmic" in low and "delete" in low)
            if not kill_keyword:
                continue
            for exe, info in tools.items():
                if exe not in low:
                    continue
                if info["category"] not in (EXPLOITATION_KILL_CATEGORIES | ANTI_ANALYSIS_KILL_CATEGORIES):
                    continue
                key = (exe, cmd)
                if key in seen:
                    continue
                seen.add(key)
                sev = "high" if info["category"] in EXPLOITATION_KILL_CATEGORIES else "medium"
                findings.append(
                    {
                        "kind": "kill_security_tool",
                        "severity": sev,
                        "tool": info["tool"],
                        "vendor": info["vendor"],
                        "category": info["category"],
                        "detail": cmd,
                    }
                )
        return findings

    def run(self):
        result = {
            "drivers_loaded": [],
            "matches": [],
            "novel_candidates": [],
            "exploitation": [],
            "service_installs": [],
            "summary": {},
        }

        evtx_zip = os.path.join(self.analysis_path, "evtx", "evtx.zip")
        if not os.path.exists(evtx_zip):
            return result

        with tempfile.TemporaryDirectory() as td:
            sysmon_paths = _extract_evtx(evtx_zip, ["Sysmon"], td)
            system_paths = _extract_evtx(evtx_zip, ["_System.evtx"], td)

            sysmon_records = []
            for p in sysmon_paths:
                sysmon_records.extend(_parse_evtx_records(p, {"1", "5", "6", "11"}))

            system_records = []
            for p in system_paths:
                system_records.extend(_parse_evtx_records(p, {"7045"}))

        executed_commands = (self.results.get("behavior") or {}).get("summary", {}).get("executed_commands") or []

        # File-create map: path → creator pid (for dropped_by_sample heuristic)
        file_creators = {}
        for rec in sysmon_records:
            if rec["eid"] == "11":
                tf = rec["data"].get("TargetFilename", "").lower()
                pid = rec["data"].get("ProcessId")
                if tf and pid:
                    file_creators[tf] = int(pid) if str(pid).isdigit() else None

        pid_name_map = self._build_pid_name_map()

        raw_service_installs = []

        # System EID 7045 — kernel-driver service installs
        for rec in system_records:
            d = rec["data"]
            ipath = d.get("ImagePath", "")
            stype = d.get("ServiceType", "")
            if ipath.lower().endswith(".sys") or "kernel" in stype.lower() or "driver" in stype.lower():
                raw_service_installs.append(
                    {
                        "service_name": d.get("ServiceName", ""),
                        "image_path": ipath,
                        "service_type": stype,
                        "time": rec.get("time"),
                    }
                )

        # Sysmon EID 6 driver loads
        seen_service_installs = set()
        for rec in sysmon_records:
            if rec["eid"] != "6":
                continue
            d = rec["data"]
            path = d.get("ImageLoaded") or d.get("ImageLoadedPath") or ""
            sha256 = ""
            for hpart in (d.get("Hashes") or "").split(","):
                if hpart.strip().lower().startswith("sha256="):
                    sha256 = hpart.split("=", 1)[1].strip().lower()
                    break
            signed = (d.get("Signed") or "").lower() == "true"
            sig_status = d.get("SignatureStatus") or ""
            signer = d.get("Signature") or ""

            creator_pid = file_creators.get(path.lower())
            created_by_sample = bool(creator_pid and creator_pid in pid_name_map)
            sample_under_test = self._is_sample_being_analyzed(path)

            driver = {
                "time": rec.get("time"),
                "path": path,
                "sha256": sha256,
                "signed": signed,
                "signature_status": sig_status,
                "signer": signer,
                "creator_pid": creator_pid,
                "creator_name": pid_name_map.get(creator_pid) if creator_pid else None,
                "created_by_sample": created_by_sample,
                "sample_under_test": sample_under_test,
            }
            result["drivers_loaded"].append(driver)

            match = self._classify_driver(driver)
            if match:
                rec_match = dict(driver)
                rec_match.update(match)
                result["matches"].append(rec_match)

            if not sample_under_test:
                novel_signals = self._classify_novel(driver, raw_service_installs)
                if novel_signals:
                    result["novel_candidates"].append({**driver, "signals": novel_signals})

            related_service_installs = []
            for svc in raw_service_installs:
                image_path = svc.get("image_path", "")
                if image_path.lower() == path.lower() or _basename(image_path) == _basename(path):
                    related_service_installs.append(svc)

            # Emit service installs that can be tied back to the analyzed sample. The
            # cmdline branch catches the common loader/dropper pattern where the sample
            # is a script/binary that invokes `sc create ... binPath=...sys ... type=kernel`
            # (or sc start) — this fires even when the .sys was extracted by the analyzer
            # itself rather than written by a monitored process, and even when the .sys
            # basename differs from the submission name. We deliberately do NOT gate on
            # path location: the analyzer drops user-uploaded samples into the same Temp
            # directories that look "suspicious", so a path-based gate would FP on an
            # analyst submitting a raw .sys to scan it.
            service_invoked_by_sample = _service_create_cmdline_for(path, _basename(path), executed_commands)
            if sample_under_test or created_by_sample or service_invoked_by_sample:
                for svc in related_service_installs:
                    dedupe_key = (
                        svc.get("service_name", ""),
                        svc.get("image_path", "").lower(),
                        svc.get("time", ""),
                    )
                    if dedupe_key in seen_service_installs:
                        continue
                    seen_service_installs.add(dedupe_key)
                    result["service_installs"].append(
                        {
                            **svc,
                            "driver_path": path,
                            "driver_sha256": sha256,
                            "sample_under_test": sample_under_test,
                            "created_by_sample": created_by_sample,
                            "creator_pid": creator_pid,
                            "creator_name": pid_name_map.get(creator_pid) if creator_pid else None,
                        }
                    )

            expl = self._correlate_eid5_kills(rec.get("time"), sysmon_records)
            if expl:
                result["exploitation"].append(
                    {
                        "driver_path": path,
                        "driver_sha256": sha256,
                        "driver_time": rec.get("time"),
                        "findings": expl,
                    }
                )

        # Cmdline-based kill correlation: emit once per analysis (not per driver) and
        # only when at least one driver actually loaded. Otherwise we'd raise a BYOD
        # exploitation signal on a non-BYOD sample that just runs taskkill.
        if result["drivers_loaded"]:
            cmdline_kills = self._correlate_kill_cmdlines(executed_commands)
            if cmdline_kills:
                result["exploitation"].append(
                    {
                        "driver_path": None,
                        "driver_sha256": None,
                        "driver_time": None,
                        "scope": "analysis",
                        "findings": cmdline_kills,
                    }
                )

        result["summary"] = {
            "drivers_loaded": len(result["drivers_loaded"]),
            "lol_matches": len(result["matches"]),
            "novel": len(result["novel_candidates"]),
            "exploitation": len(result["exploitation"]),
            "service_installs": len(result["service_installs"]),
        }
        log.info("loldrivers: %s", result["summary"])
        return result
