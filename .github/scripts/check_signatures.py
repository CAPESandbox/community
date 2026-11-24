#!/usr/bin/env python3
"""Static check for CAPEv2 community signatures.

Catches common string-escaping and regex regressions across modules/signatures/:
- Invalid escape sequences (SyntaxWarning / DeprecationWarning)
- Raw strings with doubled backslashes (r"...\\\\...") used in plain string
  comparisons (startswith/endswith/in/==/!=, check_* with regex=False)
- Accidental control-character escapes (\\a, \\b, \\f, \\v) in Windows paths
- Over-escaped raw regex patterns (\\\\ , \\\\\\\\, \\\\. before file extensions)
- Regex patterns that fail to compile with re.compile()
"""

import ast
import io
import re
import sys
import tokenize
import warnings
from collections import defaultdict
from pathlib import Path

ALWAYS_REGEX_METHODS = {"check_process_name", "yara_detected", "check_suricata_alerts"}
OPTIONAL_REGEX_METHODS = {
    "check_file",
    "check_read_file",
    "check_write_file",
    "check_delete_file",
    "check_key",
    "check_read_key",
    "check_write_key",
    "check_delete_key",
    "check_mutex",
    "check_started_service",
    "check_created_service",
    "check_executed_command",
    "check_api",
    "check_argument",
    "check_argument_call",
    "check_ip",
    "check_domain",
    "check_url",
    "_check_value",
}
RE_FUNCS = {"compile", "match", "search", "findall", "finditer", "sub", "subn", "split", "fullmatch"}
PLAIN_STR_METHODS = {
    "startswith",
    "endswith",
    "find",
    "rfind",
    "index",
    "rindex",
    "replace",
    "split",
    "rsplit",
    "strip",
    "lstrip",
    "rstrip",
    "count",
    "removeprefix",
    "removesuffix",
}
OPTIONAL_REGEX_POS = {
    "check_file": 1,
    "check_read_file": 1,
    "check_write_file": 1,
    "check_delete_file": 1,
    "check_key": 1,
    "check_read_key": 1,
    "check_write_key": 1,
    "check_delete_key": 1,
    "check_mutex": 1,
    "check_started_service": 1,
    "check_created_service": 1,
    "check_executed_command": 1,
    "check_ip": 1,
    "check_domain": 1,
    "check_url": 1,
    "check_api": 2,
    "_check_value": 2,
    "check_argument": 5,
    "check_argument_call": 5,
}
DOUBLE_BS_EXT_RE = re.compile(
    r"(?<!\\)\\\\\.(exe|dll|sys|com|bat|cmd|ps1|vbs|js|txt|html|htm|net|org|com|io|pw|xyz|me|info|co|it|default|Defender)\b", re.I
)


def _get_string_tokens(src: str) -> dict[tuple[int, int], tuple[str, bool]]:
    toks: dict[tuple[int, int], tuple[str, bool]] = {}
    fstring_start = getattr(tokenize, "FSTRING_START", None)
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.STRING or (fstring_start is not None and tok.type == fstring_start):
                text = tok.string
                prefix = ""
                for ch in text:
                    if ch in "rRbBuUfF":
                        prefix += ch
                    else:
                        break
                toks[(tok.start[0], tok.start[1])] = (text, "r" in prefix.lower())
    except tokenize.TokenError:
        pass
    return toks


def _attach_parents(tree: ast.AST) -> None:
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child._parent = parent  # type: ignore[attr-defined]
    tree._parent = None  # type: ignore[attr-defined]


def _enclosing(node: ast.AST) -> tuple[str | None, str | None]:
    cls = None
    fn = None
    cur = getattr(node, "_parent", None)
    while cur is not None:
        if fn is None and isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn = cur.name
        if cls is None and isinstance(cur, ast.ClassDef):
            cls = cur.name
        cur = getattr(cur, "_parent", None)
    return cls, fn


def _scoped_key(node: ast.AST, cls: str | None, fn: str | None) -> str | None:
    if isinstance(node, ast.Name):
        if fn is None and cls is not None:
            return f"ATTR:{cls}.{node.id}"
        return f"VAR:{cls or ''}:{fn or ''}:{node.id}"
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if node.value.id == "self" and cls is not None:
            return f"ATTR:{cls}.{node.attr}"
        return f"ATTR:{node.value.id}.{node.attr}"
    return None


def _unwrap(node: ast.AST) -> ast.AST:
    while True:
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in (
                "tuple",
                "list",
                "set",
                "frozenset",
                "sorted",
                "reversed",
                "enumerate",
                "iter",
            ):
                if node.args:
                    node = node.args[0]
                    continue
            if isinstance(node.func, ast.Attribute) and node.func.attr in (
                "items",
                "values",
                "keys",
                "lower",
                "upper",
                "strip",
                "copy",
            ):
                node = node.func.value
                continue
        if isinstance(node, ast.Subscript):
            node = node.value
            continue
        break
    return node


def _call_has_regex_true(call_node: ast.Call) -> bool:
    for kw in call_node.keywords:
        if kw.arg == "regex":
            if isinstance(kw.value, ast.Constant):
                return bool(kw.value.value)
            return True
    func_name = call_node.func.attr if isinstance(call_node.func, ast.Attribute) else None
    pos_idx = OPTIONAL_REGEX_POS.get(func_name or "")
    if pos_idx is not None and len(call_node.args) > pos_idx:
        arg = call_node.args[pos_idx]
        if isinstance(arg, ast.Constant) and arg.value is True:
            return True
    return False


def _is_re_call(call_node: ast.Call) -> bool:
    return (
        isinstance(call_node.func, ast.Attribute)
        and call_node.func.attr in RE_FUNCS
        and isinstance(call_node.func.value, ast.Name)
        and call_node.func.value.id in ("re", "re2", "regex")
    )


def _iter_str_consts(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            yield from _iter_str_consts(elt)
    elif isinstance(node, ast.Dict):
        for k in node.keys:
            if k is not None:
                yield from _iter_str_consts(k)
        for v in node.values:
            yield from _iter_str_consts(v)
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("set", "frozenset", "tuple", "list"):
        for arg in node.args:
            yield from _iter_str_consts(arg)


def _collect_node_sinks(tree: ast.AST) -> dict[int, set[str]]:
    _attach_parents(tree)
    derived: dict[str, set[str]] = defaultdict(set)
    inline_iter: dict[str, set[ast.AST]] = defaultdict(set)
    mod_globals = {
        t.id for n in getattr(tree, "body", []) if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)
    }

    def all_keys(node: ast.AST, cls: str | None, fn: str | None) -> set[str]:
        ks: set[str] = set()
        k = _scoped_key(node, cls, fn)
        if k:
            ks.add(k)
        if isinstance(node, ast.Name) and node.id in mod_globals:
            ks.add(f"VAR:::{node.id}")
        return ks

    for node in ast.walk(tree):
        cls, fn = _enclosing(node)
        if isinstance(node, (ast.For, ast.comprehension)):
            it = _unwrap(node.iter)
            skeys = all_keys(it, cls, fn)
            for tgt in ast.walk(node.target):
                if isinstance(tgt, ast.Name):
                    tk = f"VAR:{cls or ''}:{fn or ''}:{tgt.id}"
                    if skeys:
                        derived[tk] |= skeys
                    elif isinstance(it, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
                        inline_iter[tk].add(it)
        elif isinstance(node, ast.Assign):
            skeys = all_keys(_unwrap(node.value), cls, fn)
            if skeys:
                for tgt in node.targets:
                    tk = _scoped_key(tgt, cls, fn)
                    if tk:
                        derived[tk] |= skeys

    def resolve(node: ast.AST, cls: str | None, fn: str | None) -> tuple[set[str], set[ast.AST]]:
        u = _unwrap(node)
        ks = all_keys(u, cls, fn)
        inlines: set[ast.AST] = set()
        if isinstance(u, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            inlines.add(u)
        for _ in range(5):
            more: set[str] = set()
            for k in list(ks):
                more |= derived.get(k, set())
                inlines |= inline_iter.get(k, set())
            if more <= ks:
                break
            ks |= more
        return ks, inlines

    var_sinks: dict[str, set[str]] = defaultdict(set)
    node_sinks: dict[int, set[str]] = defaultdict(set)

    def mark(node: ast.AST, cls: str | None, fn: str | None, kind: str) -> None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            node_sinks[id(node)].add(kind)
        u = _unwrap(node)
        if isinstance(u, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            for c in _iter_str_consts(u):
                node_sinks[id(c)].add(kind)
        ks, inlines = resolve(node, cls, fn)
        for k in ks:
            var_sinks[k].add(kind)
        for in_n in inlines:
            for c in _iter_str_consts(in_n):
                node_sinks[id(c)].add(kind)

    for node in ast.walk(tree):
        cls, fn = _enclosing(node)
        if isinstance(node, ast.Call):
            if _is_re_call(node):
                if node.args:
                    mark(node.args[0], cls, fn, "REGEX")
                for kw in node.keywords:
                    if kw.arg == "pattern":
                        mark(kw.value, cls, fn, "REGEX")
            elif isinstance(node.func, ast.Attribute):
                m = node.func.attr
                if m in ALWAYS_REGEX_METHODS:
                    pat = node.args[0] if node.args else None
                    for kw in node.keywords:
                        if kw.arg in ("pattern", "name"):
                            pat = kw.value
                    if pat is not None:
                        mark(pat, cls, fn, "REGEX")
                elif m in OPTIONAL_REGEX_METHODS:
                    rx = _call_has_regex_true(node)
                    pat = (
                        node.args[1]
                        if (m == "check_argument_call" and len(node.args) >= 2)
                        else (node.args[0] if node.args else None)
                    )
                    for kw in node.keywords:
                        if kw.arg == "pattern":
                            pat = kw.value
                    if pat is not None:
                        mark(pat, cls, fn, "REGEX" if rx else "PLAIN")
                elif m in PLAIN_STR_METHODS:
                    for arg in node.args:
                        mark(arg, cls, fn, "PLAIN")
                    mark(node.func.value, cls, fn, "PLAIN")
        elif isinstance(node, ast.Compare):
            for n in [node.left] + list(node.comparators):
                mark(n, cls, fn, "PLAIN")

    for node in ast.walk(tree):
        cls, fn = _enclosing(node)
        if isinstance(node, ast.Assign):
            sinks: set[str] = set()
            for tgt in node.targets:
                tk = _scoped_key(tgt, cls, fn)
                if tk:
                    sinks |= var_sinks.get(tk, set())
            if sinks:
                for c in _iter_str_consts(node.value):
                    node_sinks[id(c)] |= sinks

    return node_sinks


def check_file(path: Path) -> list[str]:
    errors: list[str] = []
    src = path.read_text(encoding="utf-8", errors="replace")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", (SyntaxWarning, DeprecationWarning))
        try:
            tree = ast.parse(src, filename=str(path))
        except SyntaxError as exc:
            return [f"{path}:{exc.lineno}: SyntaxError: {exc.msg}"]

    for w in caught:
        if "invalid escape sequence" in str(w.message):
            errors.append(f"{path}:{w.lineno}: {w.message}")

    toks = _get_string_tokens(src)
    node_sinks = _collect_node_sinks(tree)

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        val = node.value
        tok_str, is_raw = toks.get((node.lineno, node.col_offset), (repr(val), False))
        kinds = node_sinks.get(id(node), set())

        if "PLAIN" in kinds and "REGEX" not in kinds:
            if is_raw and "\\\\" in val:
                errors.append(f"{path}:{node.lineno}: raw string with doubled backslash in plain comparison: {tok_str}")
            if not is_raw and "\\" in tok_str and any(c in val for c in ("\a", "\b", "\f", "\v")):
                errors.append(f"{path}:{node.lineno}: accidental control-character escape in plain string: {tok_str}")

        if "REGEX" in kinds:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", FutureWarning)
                    re.compile(val, re.IGNORECASE)
            except re.error as exc:
                errors.append(f"{path}:{node.lineno}: invalid regex ({exc}): {tok_str}")
            if is_raw and re.search(r"(?<!\\)\\\\ ", val):
                errors.append(f"{path}:{node.lineno}: over-escaped space (\\\\ ) in raw regex: {tok_str}")
            if "\\\\\\\\" in val:
                errors.append(f"{path}:{node.lineno}: over-escaped separator (\\\\\\\\) in regex: {tok_str}")
            if is_raw and DOUBLE_BS_EXT_RE.search(val):
                errors.append(f"{path}:{node.lineno}: over-escaped dot (\\\\.) in raw regex: {tok_str}")

    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[2] / "modules" / "signatures"
    all_errors: list[str] = []
    for path in sorted(root.rglob("*.py")):
        all_errors.extend(check_file(path))
    for err in all_errors:
        print(err)
    if all_errors:
        print(f"Found {len(all_errors)} signature escaping error(s).", file=sys.stderr)
        return 1
    print("Signature escaping audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
