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


_BLOCK_SCALAR_RE = re.compile(r"^[|>][0-9]*[+-]?$")
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
    """Fold a ``>`` block scalar: single line breaks become spaces, blank lines stay."""
    paragraphs: List[str] = []
    current: List[str] = []
    for line in lines:
        if line == "":
            if current:
                paragraphs.append(" ".join(current))
                current = []
            continue
        current.append(line)
    if current:
        paragraphs.append(" ".join(current))
    return "\n".join(paragraphs)


def _parse_block_scalar(
    lines: List[str], i: int, key_indent: int, indicator: str, path: Path
) -> Tuple[str, int]:
    style = indicator[0]
    chomp = "-" if indicator.endswith("-") else ("+" if indicator.endswith("+") else "")
    i += 1
    n = len(lines)
    content: List[str] = []
    base_indent: Optional[int] = None

    while i < n:
        line = lines[i]
        if line.strip() == "":
            if base_indent is not None:
                content.append("")
            i += 1
            continue
        ind = _indent(line)
        if ind <= key_indent:
            break
        if base_indent is None:
            base_indent = ind
        if ind >= base_indent:
            content.append(" " * (ind - base_indent) + line.lstrip(" "))
        else:
            content.append(" " * max(ind - base_indent, 0) + line.strip())
        i += 1

    value = "\n".join(content) if style == "|" else _fold(content)
    if chomp == "-":
        value = value.rstrip("\n")
    elif chomp == "+":
        value = value + "\n" if content else ""
    else:
        value = value.rstrip("\n") + "\n" if content else ""
    return value, i


def _parse_map_into(
    lines: List[str], i: int, indent: int, target: Dict[str, Any], path: Path
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
            child, i = _parse_block(lines, child_i, child_indent, path)
            target[key] = child
            continue
        if _BLOCK_SCALAR_RE.match(val):
            target[key], i = _parse_block_scalar(lines, i, indent, val, path)
            continue
        target[key] = _parse_scalar(val, path, i + 1)
        i += 1


def _parse_seq(lines: List[str], i: int, indent: int, path: Path) -> Tuple[List[Any], int]:
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
            child, i = _parse_block(lines, child_i, child_indent, path)
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
                        child, i = _parse_block(lines, child_i, child_indent, path)
                        item[key] = child
                        i = _parse_map_into(lines, i, key_indent, item, path)
                        result.append(item)
                        continue
                item[key] = None
                i += 1
            elif _BLOCK_SCALAR_RE.match(val):
                item[key], i = _parse_block_scalar(lines, i, key_indent, val, path)
            else:
                item[key] = _parse_scalar(val, path, i + 1)
                i += 1
            result.append(item)
            i = _parse_map_into(lines, i, key_indent, item, path)
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


def _parse_block(lines: List[str], i: int, indent: int, path: Path) -> Tuple[Any, int]:
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
        return _parse_seq(lines, i, indent, path)
    result: Dict[str, Any] = {}
    i = _parse_map_into(lines, i, indent, result, path)
    return result, i


def load_yaml(path: Union[Path, str]) -> Any:
    """Parse a YAML document from ``path`` using the supported subset, fail-closed."""
    path = Path(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    if any("\t" in line for line in lines):
        raise YamlParseError(f"YAML parse error in {path}: tabs are forbidden")
    value, i = _parse_block(lines, 0, 0, path)
    trailing = _skip_blank_and_comment(lines, i)
    if trailing < len(lines):
        raise YamlParseError(
            f"YAML parse error in {path}:{trailing + 1}: unexpected content after document"
        )
    return value
