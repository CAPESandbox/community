import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

# Rules that fire due to CAPE's own EVTX collection (wevtutil clearing logs)
DEFAULT_SUPPRESSED_RULE_IDS = {
    "d99b79d2-0a6f-4f46-ad8b-260b6e17f982",  # Security Eventlog Cleared
    "100ef69e-3327-481c-8e5c-6d80d9507556",  # Important Windows Eventlog Cleared
}
DEFAULT_SUPPRESSED_RULE_TITLES = {
    "Security Eventlog Cleared",
    "Important Windows Eventlog Cleared",
}

# Regex flag character mapping
FLAG_MAP = {
    "i": re.IGNORECASE,
    "s": re.DOTALL,
    "m": re.MULTILINE,
}


def _parse_flags(flags_str):
    """Parse flag string like 'im' into re flags int and negate bool."""
    flags = 0
    negate = False
    for ch in flags_str or "":
        if ch == "n":
            negate = True
        elif ch in FLAG_MAP:
            flags |= FLAG_MAP[ch]
        else:
            log.warning("Unknown regex flag '%s', ignoring", ch)
    return flags, negate


def _compile_match_group(group):
    """Compile a match group dict into list of (field, compiled_regex, negate)."""
    compiled = []
    for field_name, matcher in group.items():
        pattern = matcher.get("pattern", "")
        flags_str = matcher.get("flags", "")
        flags, negate = _parse_flags(flags_str)
        try:
            compiled.append((field_name, re.compile(pattern, flags), negate))
        except re.error as e:
            log.warning("Failed to compile regex '%s' for field '%s': %s", pattern, field_name, e)
            return None
    return compiled


# ---------------------------------------------------------------------------
# Boolean expression parser for match_logic
# ---------------------------------------------------------------------------
# Grammar:
#   expr     -> or_expr
#   or_expr  -> and_expr ('or' and_expr)*
#   and_expr -> not_expr ('and' not_expr)*
#   not_expr -> 'not' not_expr | atom
#   atom     -> '(' expr ')' | IDENTIFIER


class _BoolExpr:
    """Simple AST nodes for boolean match_logic expressions."""

    pass


class _And(_BoolExpr):
    def __init__(self, children):
        self.children = children

    def evaluate(self, values):
        return all(c.evaluate(values) for c in self.children)


class _Or(_BoolExpr):
    def __init__(self, children):
        self.children = children

    def evaluate(self, values):
        return any(c.evaluate(values) for c in self.children)


class _Not(_BoolExpr):
    def __init__(self, child):
        self.child = child

    def evaluate(self, values):
        return not self.child.evaluate(values)


class _Var(_BoolExpr):
    def __init__(self, name):
        self.name = name

    def evaluate(self, values):
        return values.get(self.name, False)


class _AllAnd(_BoolExpr):
    """Default: AND all group names together."""

    def __init__(self, names):
        self.names = names

    def evaluate(self, values):
        return all(values.get(n, False) for n in self.names)


def _tokenize(expr):
    tokens = []
    i = 0
    while i < len(expr):
        if expr[i].isspace():
            i += 1
        elif expr[i] == "(":
            tokens.append("(")
            i += 1
        elif expr[i] == ")":
            tokens.append(")")
            i += 1
        else:
            j = i
            while j < len(expr) and not expr[j].isspace() and expr[j] not in ("(", ")"):
                j += 1
            tokens.append(expr[i:j])
            i = j
    return tokens


def _parse_expr(tokens, pos):
    return _parse_or(tokens, pos)


def _parse_or(tokens, pos):
    left, pos = _parse_and(tokens, pos)
    children = [left]
    while pos < len(tokens) and tokens[pos] == "or":
        pos += 1
        right, pos = _parse_and(tokens, pos)
        children.append(right)
    node = children[0] if len(children) == 1 else _Or(children)
    return node, pos


def _parse_and(tokens, pos):
    left, pos = _parse_not(tokens, pos)
    children = [left]
    while pos < len(tokens) and tokens[pos] == "and":
        pos += 1
        right, pos = _parse_not(tokens, pos)
        children.append(right)
    node = children[0] if len(children) == 1 else _And(children)
    return node, pos


def _parse_not(tokens, pos):
    count = 0
    while pos < len(tokens) and tokens[pos] == "not":
        count += 1
        pos += 1
    child, pos = _parse_atom(tokens, pos)
    for _ in range(count):
        child = _Not(child)
    return child, pos


def _parse_atom(tokens, pos):
    if pos >= len(tokens):
        raise ValueError("Unexpected end of match_logic expression")
    if tokens[pos] == "(":
        pos += 1
        node, pos = _parse_expr(tokens, pos)
        if pos >= len(tokens) or tokens[pos] != ")":
            raise ValueError("Missing closing parenthesis in match_logic")
        return node, pos + 1
    if tokens[pos] in ("and", "or", "not", ")"):
        raise ValueError(f"Unexpected token '{tokens[pos]}' in match_logic")
    return _Var(tokens[pos]), pos + 1


def parse_match_logic(expr_str, group_names):
    """Parse a match_logic expression string into a callable AST node.

    Returns an _AllAnd over group_names if expr_str is empty/None.
    """
    if not expr_str:
        return _AllAnd(list(group_names))
    tokens = _tokenize(expr_str)
    if not tokens:
        return _AllAnd(list(group_names))
    node, pos = _parse_expr(tokens, 0)
    if pos != len(tokens):
        raise ValueError(f"Unexpected token '{tokens[pos]}' at position {pos} in match_logic")
    return node


# ---------------------------------------------------------------------------
# Filter loading
# ---------------------------------------------------------------------------


def _load_filters(filters_path):
    """Load and compile filters from JSON file. Returns list of compiled filter dicts."""
    if not filters_path or not os.path.exists(filters_path):
        return []

    try:
        with open(filters_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Failed to load sigma filters from %s: %s", filters_path, e)
        return []

    compiled_filters = []
    for idx, filt in enumerate(data.get("filters", [])):
        rules = filt.get("rules", [])
        if not rules:
            log.warning("Sigma filter %d has no 'rules' field, skipping", idx)
            continue

        action = filt.get("action", "")
        if action not in ("suppress", "set_score"):
            log.warning("Sigma filter %d has invalid action '%s', skipping", idx, action)
            continue

        if action == "set_score":
            if "score" not in filt:
                log.warning("Sigma filter %d has action 'set_score' but no 'score' field, skipping", idx)
                continue
            if not isinstance(filt["score"], (int, float)):
                log.warning("Sigma filter %d has non-numeric score '%s', skipping", idx, filt["score"])
                continue

        # Compile match groups
        raw_matches = filt.get("matches", {})
        compiled_groups = {}
        skip = False
        for group_name, group in raw_matches.items():
            compiled = _compile_match_group(group)
            if compiled is None:
                log.warning("Sigma filter %d: skipping due to compile error in group '%s'", idx, group_name)
                skip = True
                break
            compiled_groups[group_name] = compiled
        if skip:
            continue

        # Parse match_logic
        try:
            logic = parse_match_logic(filt.get("match_logic"), compiled_groups.keys())
        except ValueError as e:
            log.warning("Sigma filter %d: invalid match_logic: %s", idx, e)
            continue

        packages = filt.get("packages")
        if packages:
            packages = {p.lower() for p in packages}

        compiled_filters.append(
            {
                "comment": filt.get("comment", ""),
                "rules": set(rules),
                "wildcard": "*" in rules,
                "packages": packages,
                "scope": filt.get("scope", "detection"),
                "action": action,
                "score": filt.get("score"),
                "groups": compiled_groups,
                "logic": logic,
            }
        )

    log.debug("Loaded %d sigma filters from %s", len(compiled_filters), filters_path)
    return compiled_filters


def _match_group_against_event(compiled_group, event):
    """Check if a compiled match group matches a single event dict.

    Returns True if all field matchers in the group are satisfied.
    """
    for field_name, compiled_re, negate in compiled_group:
        value = event.get(field_name, "")
        if not isinstance(value, str):
            value = str(value)
        matched = bool(compiled_re.search(value))
        if negate:
            matched = not matched
        if not matched:
            return False
    return True


def _evaluate_filter_against_event(filt, event):
    """Evaluate all match groups against a single event and run match_logic.

    Returns True if the filter's logic expression is satisfied for this event.
    """
    if not filt["groups"]:
        return True

    group_results = {}
    for group_name, compiled_group in filt["groups"].items():
        group_results[group_name] = _match_group_against_event(compiled_group, event)

    return filt["logic"].evaluate(group_results)


def _filter_matches_rule(filt, title, rule_id):
    """Check if a filter applies to a given rule by title or ID."""
    if filt["wildcard"]:
        return True
    return title in filt["rules"] or rule_id in filt["rules"]


def apply_filters(detection, filters, package):
    """Apply compiled filters to a single detection dict.

    Returns:
        - None if the detection should be suppressed
        - The (possibly modified) detection dict otherwise
    """
    title = detection.get("title", "")
    rule_id = detection.get("id", "")
    matched_events = detection.get("matched_events", [])

    for filt in filters:
        if not _filter_matches_rule(filt, title, rule_id):
            continue

        if filt["packages"] and (package or "").lower() not in filt["packages"]:
            continue

        if filt["scope"] == "event" and matched_events:
            surviving_events = [evt for evt in matched_events if not _evaluate_filter_against_event(filt, evt)]

            if filt["action"] == "suppress":
                if len(surviving_events) < len(matched_events):
                    if not surviving_events:
                        return None
                    detection["matched_events"] = surviving_events
                    detection["count"] = len(surviving_events)
            elif filt["action"] == "set_score":
                # set_score at event scope: apply if any event matched
                if len(surviving_events) < len(matched_events):
                    detection["score"] = filt["score"]

        else:
            # scope == detection: check if any event satisfies the filter
            if filt["groups"]:
                if not matched_events:
                    continue
                any_match = any(_evaluate_filter_against_event(filt, evt) for evt in matched_events)
                if not any_match:
                    continue

            if filt["action"] == "suppress":
                return None
            elif filt["action"] == "set_score":
                detection["score"] = filt["score"]

    return detection


class Sigma(Processing):
    """Runs captured EVTX and Sysmon logs through Zircolite for Sigma rule matching."""

    key = "sigma"
    order = 99

    def run(self):
        self.key = "sigma"

        zircolite_path = self.options.get("zircolite_path", "/opt/zircolite/zircolite.py")
        ruleset_raw = self.options.get("ruleset", "data/sigma/rules_windows_generic.json")
        rulesets = [r.strip() for r in ruleset_raw.split(",") if r.strip()]
        timeout = int(self.options.get("timeout", 120))

        # Build suppression sets from defaults + config
        suppressed_ids = set(DEFAULT_SUPPRESSED_RULE_IDS)
        suppressed_titles = set(DEFAULT_SUPPRESSED_RULE_TITLES)

        extra_ids = self.options.get("suppress_rule_ids", "")
        if extra_ids:
            suppressed_ids.update(i.strip() for i in extra_ids.split(",") if i.strip())

        extra_titles = self.options.get("suppress_rule_titles", "")
        if extra_titles:
            suppressed_titles.update(t.strip() for t in extra_titles.split(",") if t.strip())

        # Per-rule package suppression — use the package resolved by AnalysisInfo
        # which handles auto-detected packages from the analysis log.
        package = self.results.get("info", {}).get("package", "") if self.results else ""
        if package:
            suppress_rules_section = Config("processing").fullconfig.get("sigma_suppress_rules", {})
            for rule_key, packages_str in suppress_rules_section.items():
                if not packages_str or not isinstance(packages_str, str):
                    continue
                packages = {p.strip().lower() for p in packages_str.split(",") if p.strip()}
                if "*" in packages or package.lower() in packages:
                    # UUID check: 36 chars with 4 dashes
                    if len(rule_key) == 36 and rule_key.count("-") == 4:
                        suppressed_ids.add(rule_key)
                    else:
                        suppressed_titles.add(rule_key)

        # Load JSON-based filters
        filters_path = self.options.get("filters", "data/sigma/filters.json")
        if filters_path and not os.path.isabs(filters_path):
            filters_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), filters_path)
        compiled_filters = _load_filters(filters_path)

        cape_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        resolved_rulesets = []
        for rs in rulesets:
            if not os.path.isabs(rs):
                rs = os.path.join(cape_root, rs)
            if not os.path.exists(rs):
                log.warning("Sigma ruleset not found at %s, skipping", rs)
                continue
            resolved_rulesets.append(rs)

        if not os.path.exists(zircolite_path):
            log.debug("Zircolite not found at %s", zircolite_path)
            return None

        if not resolved_rulesets:
            log.debug("No valid Sigma rulesets found")
            return None

        all_raw_detections = []

        # Scan EVTX files
        evtx_detections = self._run_evtx(zircolite_path, resolved_rulesets, timeout)
        if evtx_detections:
            all_raw_detections.extend(evtx_detections)

        # Scan Sysmon XML logs
        sysmon_detections = self._run_sysmon_xml(zircolite_path, resolved_rulesets, timeout)
        if sysmon_detections:
            all_raw_detections.extend(sysmon_detections)

        if not all_raw_detections:
            return None

        return self._process_detections(all_raw_detections, suppressed_ids, suppressed_titles, compiled_filters, package)

    def _run_zircolite(self, zircolite_path, rulesets, timeout, input_path, extra_args=None):
        """Run Zircolite with given input and return raw detections list."""
        tmpdir = None
        try:
            tmpdir = tempfile.mkdtemp(prefix="cape_sigma_")
            output_file = os.path.join(tmpdir, "sigma_output.json")

            cmd = [
                sys.executable,
                zircolite_path,
                "-e",
                input_path,
                "-o",
                output_file,
                "-q",
            ]
            for rs in rulesets:
                cmd.extend(["-r", rs])
            if extra_args:
                cmd.extend(extra_args)

            log.debug("Running Zircolite: %s", " ".join(cmd))

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=os.path.dirname(zircolite_path),
            )

            if result.returncode != 0:
                log.warning("Zircolite failed (rc=%d): %s", result.returncode, (result.stderr or "")[:500])
                return None

            if not os.path.exists(output_file):
                log.debug("No Zircolite output file generated")
                return None

            max_output_bytes = 50 * 1024 * 1024  # 50 MB
            if os.path.getsize(output_file) > max_output_bytes:
                log.warning("Zircolite output too large (%d bytes), skipping", os.path.getsize(output_file))
                return None

            with open(output_file) as f:
                return json.load(f)

        except subprocess.TimeoutExpired:
            log.warning("Zircolite timed out after %d seconds", timeout)
            return None
        except Exception as e:
            log.warning("Zircolite error: %s", e)
            return None
        finally:
            if tmpdir and os.path.exists(tmpdir):
                shutil.rmtree(tmpdir, ignore_errors=True)

    def _run_evtx(self, zircolite_path, rulesets, timeout):
        """Extract and scan EVTX files from all evtx zips (snapshots + final)."""
        evtx_dir = os.path.join(self.analysis_path, "evtx")

        if not os.path.isdir(evtx_dir):
            log.debug("No evtx directory found at %s", evtx_dir)
            return None

        # Collect all evtx zip files (evtx.zip + evtx_snapshot_*.zip)
        evtx_zips = sorted(
            os.path.join(evtx_dir, f)
            for f in os.listdir(evtx_dir)
            if f.endswith(".zip")
        )
        if not evtx_zips:
            log.debug("No evtx zip files found in %s", evtx_dir)
            return None

        tmpdir = None
        try:
            tmpdir = tempfile.mkdtemp(prefix="cape_sigma_evtx_")
            real_tmpdir = os.path.realpath(tmpdir)

            # Extract all evtx zips (snapshots are incremental, each
            # contains events since the last wipe)
            max_extracted = 5 * 1024 * 1024 * 1024  # 5 GB
            for zip_idx, evtx_zip in enumerate(evtx_zips):
                subdir = os.path.join(tmpdir, str(zip_idx))
                os.makedirs(subdir, exist_ok=True)
                try:
                    with zipfile.ZipFile(evtx_zip, "r") as zf:
                        total_uncompressed = sum(m.file_size for m in zf.infolist())
                        if total_uncompressed > max_extracted:
                            log.warning("evtx zip too large (%d bytes), skipping: %s", total_uncompressed, evtx_zip)
                            continue

                        for member in zf.infolist():
                            if (member.external_attr >> 16) & 0o170000 == 0o120000:
                                log.warning("Symlink in evtx zip rejected: %s", member.filename)
                                continue
                            target = os.path.realpath(os.path.join(subdir, member.filename))
                            if not target.startswith(os.path.realpath(subdir) + os.sep) and target != os.path.realpath(subdir):
                                log.warning("Zip slip attempt in evtx zip: %s", member.filename)
                                continue
                            zf.extract(member, subdir)
                except Exception as e:
                    log.debug("Failed to extract %s: %s", evtx_zip, e)

            # Defense-in-depth: check for symlinks after extraction
            for root, dirs, files in os.walk(tmpdir):
                for name in files + dirs:
                    if os.path.islink(os.path.join(root, name)):
                        log.warning("Symlink found in evtx: %s", name)
                        return None

            evtx_files = []
            for root, _dirs, files in os.walk(tmpdir):
                for f in files:
                    if f.lower().endswith(".evtx"):
                        evtx_files.append(os.path.join(root, f))
            if not evtx_files:
                log.debug("No .evtx files found in archive")
                return None

            # Filter analyzer noise: convert evtx to JSONL via evtx_dump,
            # strip events from the CAPE analyzer parent process, and
            # feed clean JSONL to zircolite.
            evtx_dump_bin = self.options.get("evtx_dump_bin", "/usr/local/bin/evtx_dump")
            # Load analyzer noise filter from shared config
            analyzer_exclude = set()
            try:
                filters_path = self.options.get("filters", "data/sigma/filters.json")
                filters_local = self.options.get("filters_local", "data/sigma/filters_local.json")
                for fp in [filters_path, filters_local]:
                    if fp and not os.path.isabs(fp):
                        fp = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), fp)
                    if fp and os.path.exists(fp):
                        with open(fp) as _f:
                            _data = json.load(_f)
                        _pf = _data.get("pre_filters", {})
                        for p in _pf.get("exclude_parent_processes", []):
                            analyzer_exclude.add(p.lower())
                        for p in _pf.get("exclude_image_processes", []):
                            analyzer_exclude.add(p.lower())
                        for p in _pf.get("exclude_target_paths", []):
                            analyzer_exclude.add(p.lower())
            except Exception:
                pass
            if not analyzer_exclude:
                analyzer_exclude = {"icacls.exe", "python.exe", "wevtutil.exe", "conhost.exe"}
            # Compile a single regex for efficient matching
            exclude_re = re.compile("|".join(re.escape(p) for p in analyzer_exclude), re.IGNORECASE)

            if os.path.isfile(evtx_dump_bin):
                filtered_dir = os.path.join(tmpdir, "filtered")
                os.makedirs(filtered_dir, exist_ok=True)
                has_filtered = False
                for evtx_file in evtx_files:
                    try:
                        # Use unique name per snapshot to avoid collisions
                        rel_path = os.path.relpath(evtx_file, tmpdir)
                        basename = rel_path.replace(os.sep, "_").rsplit(".", 1)[0] + ".json"
                        jsonl_path = os.path.join(filtered_dir, basename)
                        # Stream output line-by-line to avoid loading all into memory
                        proc = subprocess.Popen(
                            [evtx_dump_bin, "-o", "jsonl", evtx_file],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                        )
                        with open(jsonl_path, "w") as out:
                            for line in proc.stdout:
                                line = line.rstrip("\n")
                                if not line.strip():
                                    continue
                                # Check specific JSON fields rather than substring on whole line
                                try:
                                    evt = json.loads(line)
                                    event_data = evt.get("Event", {}).get("EventData", {})
                                    image = str(event_data.get("Image", ""))
                                    parent = str(event_data.get("ParentImage", ""))
                                    target = str(event_data.get("TargetFilename", ""))
                                    if exclude_re.search(image) or exclude_re.search(parent) or exclude_re.search(target):
                                        continue
                                except (json.JSONDecodeError, AttributeError):
                                    pass
                                out.write(line + "\n")
                        proc.wait(timeout=120)
                        if os.path.getsize(jsonl_path) > 0:
                            has_filtered = True
                    except Exception as e:
                        log.debug("evtx_dump filter failed for %s: %s", evtx_file, e)

                if has_filtered:
                    return self._run_zircolite(
                        zircolite_path, rulesets, timeout, filtered_dir,
                        extra_args=["--jsonl"]
                    )
                log.debug("evtx_dump filtering produced no output, falling back to raw evtx")

            return self._run_zircolite(zircolite_path, rulesets, timeout, tmpdir)
        except Exception as e:
            log.warning("EVTX sigma scan failed: %s", e)
            return None
        finally:
            if tmpdir and os.path.exists(tmpdir):
                shutil.rmtree(tmpdir, ignore_errors=True)

    def _run_sysmon_xml(self, zircolite_path, rulesets, timeout):
        """Scan Sysmon XML logs if present."""
        sysmon_xml = os.path.join(self.analysis_path, "sysmon", "sysmon.xml")

        if not os.path.exists(sysmon_xml) or os.path.getsize(sysmon_xml) < 100:
            return None

        log.debug("Scanning Sysmon XML: %s", sysmon_xml)
        return self._run_zircolite(zircolite_path, rulesets, timeout, sysmon_xml, extra_args=["-x"])

    def _process_detections(self, raw_detections, suppressed_ids, suppressed_titles, compiled_filters, package):
        stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        all_techniques = set()
        seen_rules = {}  # Deduplicate by rule ID
        max_matched_events = 1000  # Cap per detection to prevent memory bloat

        # Phase 1: Legacy suppression + deduplication
        deduped = []
        for detection in raw_detections:
            title = detection.get("title", "")
            rule_id = detection.get("id", "")
            level = detection.get("rule_level", "unknown").lower()

            # Apply legacy suppression
            if rule_id in suppressed_ids:
                continue
            if title in suppressed_titles:
                continue

            # Extract MITRE info from tags
            techniques = []
            tactics = []
            for tag in detection.get("tags", []):
                if tag.startswith("attack.t"):
                    techniques.append(tag.replace("attack.", "").upper())
                elif tag.startswith("attack."):
                    tactics.append(tag.replace("attack.", "").replace("_", " ").title())

            matched_events = detection.get("matches", [])

            # Merge if same rule detected in both EVTX and Sysmon
            if rule_id and rule_id in seen_rules:
                existing = seen_rules[rule_id]
                if len(existing["matched_events"]) < max_matched_events:
                    remaining = max_matched_events - len(existing["matched_events"])
                    existing["matched_events"].extend(matched_events[:remaining])
                existing["count"] = len(existing["matched_events"])
                continue

            det = {
                "title": title,
                "id": rule_id,
                "description": detection.get("description", ""),
                "level": level,
                "count": len(matched_events[:max_matched_events]),
                "tags": detection.get("tags", []),
                "mitre_techniques": techniques,
                "mitre_tactics": tactics,
                "sigma_query": detection.get("sigma", ""),
                "matched_events": matched_events[:max_matched_events],
            }

            deduped.append(det)
            if rule_id:
                seen_rules[rule_id] = det

        # Phase 2: Apply JSON-based filters after deduplication
        detections = []
        for det in deduped:
            if compiled_filters:
                result = apply_filters(det, compiled_filters, package or "")
                if result is None:
                    continue
                det = result

            # Collect MITRE techniques only from surviving detections
            all_techniques.update(det.get("mitre_techniques", []))

            detections.append(det)
            stats["total"] += 1
            level = det["level"]
            if level in stats:
                stats[level] += 1

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        detections.sort(key=lambda d: severity_order.get(d["level"], 5))

        return {
            "detections": detections,
            "statistics": stats,
            "mitre_techniques": sorted(all_techniques),
        }
