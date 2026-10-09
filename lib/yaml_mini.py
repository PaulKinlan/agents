#!/usr/bin/env python3
"""Minimal, stdlib-only YAML subset parser.

The factory's own manifests (agents/*/agent.yaml, targets/*.yaml, lines/*.yaml)
are simple enough for the indentation-aware ``load_yaml_simple`` already shipped
in ``factory`` and ``lib/scheduler``. The CI action manifest
(``.github/actions/**/*.yml``) additionally uses two YAML features those loaders
do not support: a list of mappings (``steps: - name: ...``) and block scalars
(``run: |`` and ``description: >-``). This module covers exactly that subset and
fails closed on anything it does not understand, so a mis-parse can never turn
into a silently weaker assertion.

It is deliberately not a general YAML reader: anchors, aliases, tags, multiple
documents, and explicit typing are rejected rather than guessed.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

__all__ = ["load_yaml", "YamlParseError"]


class YamlParseError(ValueError):
    """Raised when a manifest uses a YAML construct this parser does not support."""


# A block scalar header: `|`/`>` optionally followed by a single-digit indentation indicator
# (1-9) and/or a chomping indicator, in EITHER order - YAML allows both `|2-` and `|-2`, and
# the second form used to fail this regex, so a valid document raised instead of parsing
# (agents-m8h). `|0` matches here on purpose: the parser rejects it by name, which is a better
# error than treating the whole header as a plain scalar string.
_BLOCK_SCALAR_RE = re.compile(r"^[|>](?:[0-9][+-]?|[+-][0-9]?)?$")
_FLOW_ITEM_SPLIT_RE = re.compile(r",(?![^\[\]{}]*[\]}])")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _skip_blank_and_comment(lines: List[str], i: int) -> int:
    n = len(lines)
    while i < n:
        stripped = lines[i].strip()
        if stripped == "" or stripped.startswith("#"):
            i += 1
        else:
            break
    return i


def _parse_scalar(raw: str, path: Path, lineno: int) -> Any:
    val = raw.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
        return val[1:-1]
    if val == "":
        return ""
    if val.lower() in ("true", "false"):
        return val.lower() == "true"
    if val.lower() in ("null", "~"):
        return None
    if re.fullmatch(r"-?[0-9]+", val):
        return int(val)
    if re.fullmatch(r"-?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", val):
        return float(val)
    if val.startswith(("&", "*", "!", "%", "`")):
        raise YamlParseError(
            f"YAML parse error in {path}:{lineno}: unsupported YAML construct: {val}"
        )
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(item, path, lineno)
                for item in _FLOW_ITEM_SPLIT_RE.split(inner) if item.strip()]
    if val.startswith("{") and val.endswith("}"):
        inner = val[1:-1].strip()
        result: Dict[str, Any] = {}
        if not inner:
            return result
        for pair in _FLOW_ITEM_SPLIT_RE.split(inner):
            if ":" not in pair:
                raise YamlParseError(
                    f"YAML parse error in {path}:{lineno}: malformed flow mapping: {val}"
                )
            k, v = pair.split(":", 1)
            result[k.strip()] = _parse_scalar(v, path, lineno)
        return result
    if val.startswith("[") or val.startswith("{"):
        raise YamlParseError(
            f"YAML parse error in {path}:{lineno}: malformed flow collection: {val}"
        )
    return val


def _split_mapping_entry(stripped: str, path: Path, lineno: int) -> Tuple[str, Optional[str]]:
    if ":" not in stripped:
        raise YamlParseError(
            f"YAML parse error in {path}:{lineno}: expected 'key: value', got: {stripped!r}"
        )
    key, val = stripped.split(":", 1)
    key = key.strip()
    if not key or not re.match(r"^[A-Za-z0-9_-]+$", key):
        raise YamlParseError(
            f"YAML parse error in {path}:{lineno}: invalid mapping key: {key!r}"
        )
    val = val.strip()
    return key, (val if val else None)


def _fold(lines: List[str]) -> str:
    """Fold a ``>`` block scalar: single line breaks become spaces, blank lines become newlines.

    Line breaks adjacent to more-indented lines (lines starting with leading spaces) are
    preserved as newlines rather than folded into spaces.

    Derivation against PyYAML 6.0.1 (agents-m8h), because the rule for a blank line before a
    MORE-INDENTED line is not the same as for one before an ordinary line:

        a | b        -> 'a b'        line break folds to a space
        a || b       -> 'a\nb'       one empty line contributes one newline
        a ||| b      -> 'a\n\nb'     each empty line contributes one newline
        a | ind      -> 'a\n  ind'   a more-indented line is never folded onto
        a || ind     -> 'a\n\n  ind' one empty line AND the indent break
        a ||| ind    -> 'a\n\n\n  ind'
        a | ind | b  -> 'a\n  ind\nb' the break after a more-indented line stays a newline

    The last three are why this is not simply "count the empty lines": an empty line before a
    more-indented line yields one newline for the empty line plus one for the break it cannot
    absorb, which is the case the previous implementation folded away.
    """
    if not lines:
        return ""
    chunks: List[str] = []
    pending_blanks = 0
    prev_indented = False
    for line in lines:
        if line == "":
            pending_blanks += 1
            continue
        indented = line.startswith(" ")
        if pending_blanks:
            # This also covers leading empty lines: PyYAML treats an empty line before the
            # first content line as content (`k: >` then a blank then `  a` gives '\na\n'),
            # so the separator is computed the same way whether or not anything precedes it.
            # Each surrounding MORE-INDENTED neighbour adds a break that cannot be absorbed:
            # `a | ind | (blank) | b` keeps two newlines, since the break after the indented
            # line is preserved and the empty line is a newline of its own. It is at most ONE
            # extra break even when both neighbours are more-indented - with an empty line in
            # between there is only one break left to preserve (PyYAML: `ind | (blank) | ind`
            # keeps two newlines, not three). The FIRST content line gets no extra break,
            # because there is no preceding break to preserve: with an explicit indicator that
            # leaves leading spaces in the content, `>1` then a blank then content at 2 gives
            # one newline, not two (PyYAML 6.0.1, agents-m8h).
            extra = 0 if not chunks else (1 if (indented or prev_indented) else 0)
            chunks.append("\n" * (pending_blanks + extra))
        elif chunks:
            chunks.append("\n" if (indented or prev_indented) else " ")
        chunks.append(line)
        pending_blanks = 0
        prev_indented = indented
    # Trailing empty lines are content only for keep chomping, which reaches here through the
    # caller's slice for the other two styles; they keep contributing one newline each.
    if pending_blanks:
        chunks.append("\n" * pending_blanks)
    return "".join(chunks)


def _parse_block_scalar(
    lines: List[str],
    i: int,
    key_indent: int,
    indicator: str,
    path: Path,
    ends_with_nl: bool = True,
) -> Tuple[str, int]:
    style = indicator[0]
    # Detected by PRESENCE, not by suffix: the chomping indicator may precede the digit
    # (`|-2`), so "ends with '-'" silently became clip chomping for that order.
    chomp = "-" if "-" in indicator else ("+" if "+" in indicator else "")
    # An explicit indentation indicator (`|2`, `>2`, `|2-`) fixes the content indentation
    # relative to the parent node; it is not decoration. It was accepted by _BLOCK_SCALAR_RE
    # and never read, so `|2` with content at 4 was parsed as content at 4 (agents-m8h).
    # YAML allows 1-9; 0 is invalid, and PyYAML refuses it.
    _indicator_digits = re.search(r"[0-9]+", indicator)
    declared_indent = int(_indicator_digits.group()) if _indicator_digits else None
    if declared_indent == 0:
        raise YamlParseError(
            f"YAML parse error in {path}:{i + 1}: invalid indentation indicator "
            f"'0' in {indicator!r} (YAML allows 1-9)"
        )
    i += 1
    n = len(lines)
    content: List[str] = []
    # With an explicit indicator the base is known before the first content line, so a leading
    # empty line is content and cannot postpone it (PyYAML: `|2` then a blank yields a leading
    # newline). Without one it is detected from the first non-empty line, as before.
    base_indent: Optional[int] = (key_indent + declared_indent) if declared_indent else None
    # Highest indentation seen on a whitespace-only line before the base was known. PyYAML
    # REFUSES a block whose leading empty-ish lines are more indented than the content that
    # follows, so this is tracked to fail closed rather than to guess an indent from it.
    leading_ws_indent = 0

    while i < n:
        line = lines[i]
        if line.strip() == "":
            ind_ws = _indent(line)
            if base_indent is None:
                leading_ws_indent = max(leading_ws_indent, ind_ws)
                content.append("")
            else:
                # A whitespace-only line can carry residual content, because the block's
                # indent is what gets stripped: under a base of 4, a line of five spaces is
                # one space. This holds for an INFERRED base as much as a declared one -
                # `k: >` then content at 4 then a line of five spaces keeps that space in
                # PyYAML, and collapsing it to "" lost it (cross-family review of
                # agents-m8h; pre-existing, and invisible here until the sweep covered
                # whitespace-only lines deeper than the base).
                content.append(" " * max(ind_ws - base_indent, 0))
            i += 1
            continue
        ind = _indent(line)
        if ind <= key_indent:
            break
        if base_indent is None:
            base_indent = ind
            if leading_ws_indent > base_indent:
                raise YamlParseError(
                    f"YAML parse error in {path}:{i + 1}: a whitespace-only line before the "
                    f"block content is more indented ({leading_ws_indent}) than the content "
                    f"it precedes ({base_indent})"
                )
        if declared_indent is not None and ind < base_indent:
            raise YamlParseError(
                f"YAML parse error in {path}:{i + 1}: line is less indented than the "
                f"declared indentation indicator {indicator!r} requires ({declared_indent})"
            )
        if ind >= base_indent:
            content.append(" " * (ind - base_indent) + line.lstrip(" "))
        else:
            content.append(" " * max(ind - base_indent, 0) + line.strip())
        i += 1

    last_line_has_nl = ends_with_nl if i >= n else True

    has_non_blank = any(l != "" for l in content)
    if not has_non_blank:
        if chomp == "+":
            n_nl = len(content) if last_line_has_nl else max(len(content) - 1, 0)
            return "\n" * n_nl, i
        return "", i

    last_nb_idx = max(idx for idx, l in enumerate(content) if l != "")

    if chomp == "-":
        active_lines = content[:last_nb_idx + 1]
        val = "\n".join(active_lines) if style == "|" else _fold(active_lines)
        return val, i
    elif chomp == "+":
        val = "\n".join(content) if style == "|" else _fold(content)
        if last_line_has_nl:
            val += "\n"
        return val, i
    else:
        # Clip chomping: keep content up to last non-blank line,
        # with final newline if the last non-blank line had a newline.
        active_lines = content[:last_nb_idx + 1]
        val = "\n".join(active_lines) if style == "|" else _fold(active_lines)
        last_nb_had_nl = (last_nb_idx < len(content) - 1) or last_line_has_nl
        if last_nb_had_nl:
            val += "\n"
        return val, i


def _parse_map_into(
    lines: List[str],
    i: int,
    indent: int,
    target: Dict[str, Any],
    path: Path,
    ends_with_nl: bool = True,
) -> int:
    while True:
        i = _skip_blank_and_comment(lines, i)
        if i >= len(lines):
            return i
        line = lines[i]
        cur = _indent(line)
        if cur < indent:
            return i
        if cur > indent:
            raise YamlParseError(
                f"YAML parse error in {path}:{i + 1}: unexpected indentation {cur} "
                f"(expected {indent})"
            )
        stripped = line.strip()
        if stripped.startswith("- "):
            return i
        key, val = _split_mapping_entry(stripped, path, i + 1)
        if val is None:
            child_i = _skip_blank_and_comment(lines, i + 1)
            if child_i >= len(lines):
                target[key] = None
                return child_i
            child_indent = _indent(lines[child_i])
            if child_indent <= indent:
                target[key] = None
                i = child_i
                continue
            child, i = _parse_block(lines, child_i, child_indent, path, ends_with_nl)
            target[key] = child
            continue
        if _BLOCK_SCALAR_RE.match(val):
            target[key], i = _parse_block_scalar(lines, i, indent, val, path, ends_with_nl)
            continue
        target[key] = _parse_scalar(val, path, i + 1)
        i += 1


def _parse_seq(
    lines: List[str],
    i: int,
    indent: int,
    path: Path,
    ends_with_nl: bool = True,
) -> Tuple[List[Any], int]:
    result: List[Any] = []
    while True:
        i = _skip_blank_and_comment(lines, i)
        if i >= len(lines):
            return result, i
        line = lines[i]
        cur = _indent(line)
        if cur < indent:
            return result, i
        if cur != indent:
            raise YamlParseError(
                f"YAML parse error in {path}:{i + 1}: unexpected indentation {cur} "
                f"(expected {indent})"
            )
        stripped = line.strip()
        if not stripped.startswith("- "):
            return result, i

        remainder = stripped[2:].strip()
        if not remainder:
            child_i = _skip_blank_and_comment(lines, i + 1)
            if child_i >= len(lines):
                result.append(None)
                return result, child_i
            child_indent = _indent(lines[child_i])
            if child_indent <= indent:
                result.append(None)
                i = child_i
                continue
            child, i = _parse_block(lines, child_i, child_indent, path, ends_with_nl)
            result.append(child)
            continue

        if _is_mapping_remainder(remainder):
            item: Dict[str, Any] = {}
            key, val = _split_mapping_entry(remainder, path, i + 1)
            key_indent = indent + 2
            if val is None:
                child_i = _skip_blank_and_comment(lines, i + 1)
                if child_i < len(lines):
                    child_indent = _indent(lines[child_i])
                    if child_indent > indent:
                        child, i = _parse_block(lines, child_i, child_indent, path, ends_with_nl)
                        item[key] = child
                        i = _parse_map_into(lines, i, key_indent, item, path, ends_with_nl)
                        result.append(item)
                        continue
                item[key] = None
                i += 1
            elif _BLOCK_SCALAR_RE.match(val):
                item[key], i = _parse_block_scalar(lines, i, key_indent, val, path, ends_with_nl)
            else:
                item[key] = _parse_scalar(val, path, i + 1)
                i += 1
            result.append(item)
            i = _parse_map_into(lines, i, key_indent, item, path, ends_with_nl)
            continue

        result.append(_parse_scalar(remainder, path, i + 1))
        i += 1


def _is_mapping_remainder(remainder: str) -> bool:
    """True when ``- name: value`` introduces a mapping item rather than a scalar."""
    in_single = in_double = False
    for idx, ch in enumerate(remainder):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == ":" and not in_single and not in_double:
            return idx > 0
    return False


def _parse_block(
    lines: List[str],
    i: int,
    indent: int,
    path: Path,
    ends_with_nl: bool = True,
) -> Tuple[Any, int]:
    i = _skip_blank_and_comment(lines, i)
    if i >= len(lines):
        return {}, i
    line = lines[i]
    cur = _indent(line)
    if cur != indent:
        raise YamlParseError(
            f"YAML parse error in {path}:{i + 1}: unexpected indentation {cur} "
            f"(expected {indent})"
        )
    if line.strip().startswith("- "):
        return _parse_seq(lines, i, indent, path, ends_with_nl)
    result: Dict[str, Any] = {}
    i = _parse_map_into(lines, i, indent, result, path, ends_with_nl)
    return result, i


def load_yaml(path: Union[Path, str]) -> Any:
    """Parse a YAML document from ``path`` using the supported subset, fail-closed."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if "\t" in text:
        raise YamlParseError(f"YAML parse error in {path}: tabs are forbidden")
    ends_with_nl = text.endswith(("\n", "\r"))
    lines = text.splitlines()
    value, i = _parse_block(lines, 0, 0, path, ends_with_nl)
    trailing = _skip_blank_and_comment(lines, i)
    if trailing < len(lines):
        raise YamlParseError(
            f"YAML parse error in {path}:{trailing + 1}: unexpected content after document"
        )
    return value
