#!/usr/bin/env python3
"""Deterministic, decoder-driven salvage of a model's near-JSON report (agents-lb0w3).

Why this module exists (CAP nightly, reported through coord): modern-web's model failed to parse
twice in one night. Attempt 1 wrote a JS expression where JSON wanted a string
(`"candidate_id": path.replace("/", "-")`); attempt 2 wrote unescaped double quotes inside its own
`summary` string (`"Found 3 "modern" APIs"`). Both payloads WERE report-shaped - a reader can see the
findings in them - but a single syntax error makes `json.loads` reject the whole object, so the station
lost its verdict, `classify_unparseable` called it `no_json` ("the model did not answer in the
contract's shape at all", which is untrue here), and the repair-retry was handed no hint about what was
actually wrong.

Two things are needed, and neither of them may guess:

1. `repair_json` - a bounded repair pass whose EVERY step is justified by the decoder's OWN error
   position, never by a pattern the text merely resembles. The decoder says "Expecting ',' delimiter"
   at char 41 and char 41 is a `"`: that quote cannot have been meant as the end of the string, so it
   is escaped. Same for the quote that ended a string too early (the decoder then chokes on the prose
   immediately after it) and for a trailing comma before `}`/`]`. When no step is justified the ORIGINAL
   text is returned with no notes, so a repair can never make a payload worse, and the caller's strict
   parse still decides. It is deliberately NOT a JSON-with-errors library: it evaluates nothing,
   invents nothing, and refuses to touch a value that is not a JSON literal.

2. `describe_unrepairable` - the honest half. An unquoted JS expression cannot be recovered
   deterministically (its value depends on data we do not have, and fabricating a string would poison
   candidate identity, which the whole accounting check rests on), so it is NAMED with the offset and a
   bounded excerpt instead. That name is what the operator reads and what the repair-retry prompt is
   told to fix.
"""

import json
import re
from typing import List, Optional, Tuple

# A repair pass is bounded because each step re-decodes the whole region: forty steps is already far
# past the number of syntax errors any one completion has shown, and a pathological document must not
# turn a parse failure into a quadratic scan.
MAX_REPAIR_STEPS = 40

# An excerpt in a failure line is for a human skimming a nightly report, not for reproduction: the raw
# output file is the evidence.
_EXCERPT_CHARS = 80


# A payload can carry prose with braces in it before the report (`Reading {"tool": "read"} first.`),
# so "first { to last }" is not the report - it is only the FIRST guess. Each guess costs one decode.
_MAX_REGION_ATTEMPTS = 24


def _candidate_spans(text: str) -> List[Tuple[int, int]]:
    """`(start, end)` spans to try, one per `{`, each ending at the last `}` - bounded.

    The first span is the whole-brace guess `extract_json_from_output` grew up with; the rest let a
    report that follows prose-with-braces be repaired, which a single guess cannot do (found by the
    first test written for it: `prose {with a brace}` before the object made the pass refuse a payload
    it could have fixed).
    """
    if not isinstance(text, str):
        return []
    end = text.rfind("}")
    if end <= 0:
        return []
    spans: List[Tuple[int, int]] = []
    index = text.find("{")
    while index != -1 and index < end and len(spans) < _MAX_REGION_ATTEMPTS:
        spans.append((index, end))
        index = text.find("{", index + 1)
    return spans


def _preferred_span(text: str) -> Optional[Tuple[int, int]]:
    """The span most likely to be the report itself, for describing a failure: one naming `findings`."""
    spans = _candidate_spans(text)
    for start, end in spans:
        if '"findings"' in text[start:end]:
            return start, end
    return spans[0] if spans else None


def _excerpt(fragment: str) -> str:
    """One bounded, single-line excerpt of a fragment, for a failure line."""
    line = fragment.split("\n", 1)[0]
    if len(line) > _EXCERPT_CHARS:
        line = line[:_EXCERPT_CHARS] + "..."
    return line


# A complete JSON string token: ESCAPES COUNT (agents-4lpo3). The first cut used `[^"\\\n]*`, which
# refuses any token containing an escape, so `["a" "b\\c"]` slipped past the separate-value guard - the
# repair escaped the adjacent quote and returned the single value `a" "b\\c`, exactly the fabrication the
# guard exists to prevent. The same blindness was in the object-member guard.
_QUOTED_TOKEN = r'"(?:[^"\\]|\\.)*"'


def _prev_nonspace(body: str, position: int) -> int:
    """The index of the last non-space character before `position`, or -1."""
    index = position - 1
    while index >= 0 and body[index] in " \t\r\n":
        index -= 1
    return index


def _looks_like_object_member(body: str, quote_position: int) -> bool:
    """True when the quote at `quote_position` opens a `"name":` pair rather than sitting in a string.

    THE ONE THING THAT MAKES ESCAPING SAFE. `{"a": "x" "b": 1}` is a MISSING COMMA between two members;
    escaping the quote the decoder stopped at would fold two members into one string value - a decodable
    report whose content nobody wrote, which is exactly the silent corruption this module must not
    produce. The shape is distinguishable: what follows is a complete quoted name and then a colon.
    Refusing it costs a repair we might have got away with (prose can contain `"word":`), and a named
    failure is worth more than a guess with a fabricated payload behind it.
    """
    return re.match(_QUOTED_TOKEN + r'\s*:', body[quote_position:]) is not None


def _starts_a_separate_value(body: str, quote_position: int) -> bool:
    """True when the quote at `quote_position` opens a WHOLE value of its own, not prose inside one.

    THE ARRAY SIDE OF THE MISSING-COMMA AMBIGUITY (agents-9tw8i). `{"tags": ["a" "b"]}` and
    `{"summary": "Found "modern" APIs"}` look identical to the decoder - both stop at a quote after a
    complete string - and the first cut of this module escaped both. That turned the first into ONE
    string `a "b`, a decodable report whose content nobody wrote: the silent corruption
    `_looks_like_object_member` already prevents on the object side, unfixed on the array side.

    The discriminator is FORWARD, because that is where the two shapes differ: a separate value is a
    complete quoted token that ends the collection (`"b"]`, `"b"}`, `"b",`), while prose inside a string
    keeps going as words. Refusing costs a repair we might have got away with (a one-word quote inside
    an array element), and a named failure is worth more than a fabricated payload.
    """
    # The followers: a collection closer, a comma, or ANOTHER value's opening quote (three adjacent
    # strings are three values, agents-4lpo3's P3 symptom).
    return re.match(_QUOTED_TOKEN + r'\s*["}}\],]', body[quote_position:]) is not None


def _one_repair(body: str, error: "json.JSONDecodeError") -> Optional[Tuple[str, str]]:
    """The single repair the decoder's error justifies, or None if it justifies none.

    Returns `(repaired_body, note)`. Every branch names the fact from the decoder that licenses it;
    there is no branch that fires on "this looks like broken JSON".
    """
    position = error.pos
    message = error.msg
    if position >= len(body):
        # The document ended before this point: that is truncation, and classify_unparseable owns it.
        return None
    char = body[position]

    if ("delimiter" in message and char == '"'
            and not _looks_like_object_member(body, position)
            and not _starts_a_separate_value(body, position)):
        # "Expecting ',' delimiter" AT a quote means the decoder had already finished a string and
        # found another quote where a comma belonged - i.e. the string contained a literal quote.
        return (body[:position] + '\\"' + body[position + 1:],
                f"escaped the unescaped quote at char {position} ({message})")

    if "delimiter" in message:
        index = _prev_nonspace(body, position)
        # THE ERROR POSITION DECIDES WHETHER THE PREVIOUS QUOTE IS THE CULPRIT (agents-9tw8i). When the
        # decoder stopped AT a quote that opens a whole value of its own - an object member (`"b":`) or a
        # separate array value (`"b"]`) - the missing piece is a COMMA: escaping the quote before it
        # would splice two values into one string (`["a" "b"]` -> `a "b`), which is the fabrication this
        # module refuses. When it stopped on prose instead (CAP's `"Found "modern" APIs`), the quote
        # before it IS the culprit and rule 2 is the repair. Guarding on the position rather than on the
        # preceding quote is what makes both true: an earlier cut guarded the preceding quote, which
        # ends in the model's prose followed by `",` and therefore matched the separate-value pattern by
        # construction - it refused every prose-quote repair, the CAP case included.
        missing_separator = char == '"' and (_looks_like_object_member(body, position)
                                             or _starts_a_separate_value(body, position))
        if (index >= 0 and body[index] == '"'
                and not _looks_like_object_member(body, index)
                and not missing_separator):
            # The mirror image, which is how a prose quote PAIR continues: the decoder accepted a string
            # that ended too early, skipped the space after it and then choked on prose ('A' in
            # `"Found 3 \\"modern" APIs`). The quote before the error ended that string too early.
            # REPLACED by its escaped form, never prefixed: inserting a backslash before an
            # already-escaped quote produces `\\\\"` + `"` and walks the same error rightwards on every
            # step - how the first cut of this module spent its whole bound changing nothing.
            return (body[:index] + '\\"' + body[index + 1:],
                    f"escaped the quote that ended a string early at char {index} ({message})")

    if char in '}]' and ("property name" in message or message.startswith("Expecting value")):
        # "Expecting property name enclosed in double quotes" at a closer (an object) or "Expecting
        # value" at a closer (an array): what precedes it is a comma with nothing after it, which JSON
        # forbids while every other comma is fine.
        index = _prev_nonspace(body, position)
        if index >= 0 and body[index] == ",":
            return (body[:index] + body[index + 1:],
                    f"removed the trailing comma at char {index} before {char!r}")
    return None


def repair_json(text: str) -> Tuple[str, List[str]]:
    """Salvage `text` into decodable JSON, or hand it back untouched with no notes.

    The contract callers depend on: the returned notes are EMPTY unless the returned text decodes as
    one JSON value, so `notes` can be read as "a repair was applied and it worked". Nothing here
    decides whether the result is a usable REPORT - `extract_json_from_output` and the report schema
    still own that, unchanged.
    """
    for start, end in _candidate_spans(text):
        repaired, notes = _repair_span(text[start:end + 1])
        if notes:
            return text[:start] + repaired + text[end + 1:], notes
    return text, []


def _repair_span(body: str) -> Tuple[str, List[str]]:
    """One bounded repair pass over ONE candidate span. `(repaired_body, notes)`; notes empty on failure."""
    repaired = body
    notes: List[str] = []
    for _step in range(MAX_REPAIR_STEPS):
        try:
            json.loads(repaired)
            return repaired, notes
        except json.JSONDecodeError as error:
            step = _one_repair(repaired, error)
            if step is None:
                # No repair is justified by this error: this span is not salvageable, and a PARTIAL
                # repair must never be handed back (the caller would parse text nobody wrote).
                return body, []
            repaired, note = step
            notes.append(note)
    # The step bound is exhausted: the document has more syntax errors than a repair pass may spend on
    # it, and an unverified repair is worse than the honest failure.
    return body, []


def describe_unrepairable(text: str) -> Optional[str]:
    """Name a syntax error we will not repair, for the no-verdict reason and the repair-retry hint.

    Only two shapes are named, and both are named as FACTS about the decoder's error rather than as
    guesses about intent:

    * an unquoted expression where a JSON value belongs (`"candidate_id": path.replace("/", "-")`) -
      deterministic repair is impossible: the value depends on data the factory does not have, and
      inventing a string would bind a finding to a candidate id nobody wrote;
    * a string whose unescaped quote could not be escaped within the bound, reported with the offset so
      the retry can be told which string to fix;
    * a missing separator - the comma between two adjacent members or values, or the colon after a
      member name - named as the separator the decoder asked for rather than as the unescaped quote it
      stopped on (agents-fsrqw: both arrive as "Expecting ... delimiter").

    Returns None when the payload is decodable (nothing to say) or when the error is one this function
    has no better words for than the caller's own.
    """
    span = _preferred_span(text)
    if span is None:
        return None
    start, end = span
    body = text[start:end + 1]
    try:
        json.loads(body)
        return None
    except json.JSONDecodeError as exc:
        # Bound to a NEW name: Python deletes `except ... as error` at the end of the clause, so reading
        # that name afterwards is an UnboundLocalError instead of the error that was actually caught.
        error = exc
    position = error.pos
    message = error.msg
    char = body[position] if position < len(body) else ""
    if char in '}]' and ("property name" in message or message.startswith("Expecting value")):
        # A closer where a member or a value belongs: a comma with nothing after it that the repair pass
        # declined to remove (it only removes one the decoder points at, one per step).
        return (f"a collection at char {position} closes after a comma with no value before it "
                f"({_excerpt(body[max(position - 40, 0):position + 1])!r})")
    if message.startswith("Expecting value") and char and char not in '"{[-0123456789tfn':
        # A value position holding something that is not a JSON literal. JSON strings must be quoted,
        # so this is prose or an expression, never a value.
        return (f"a value at char {position} is not a JSON literal: `{_excerpt(body[position:])}` - "
                f"unquoted text or an expression where a quoted string was required, which no "
                f"deterministic repair can recover")
    if "delimiter" in message:
        index = _prev_nonspace(body, position)
        quote_at_error = char == '"'
        quote_before = index >= 0 and body[index] == '"'
        # A MISSING SEPARATOR IS NOT AN UNESCAPED QUOTE (agents-fsrqw). Both arrive as "delimiter", so
        # the message text - which delimiter the decoder wanted - is read before the character it
        # stopped on. Naming these matters because they are what the retry gets told: `[{"a": 1}
        # {"b": 2}]` is a missing comma between two rows, and "unescaped quote" would send the model
        # looking for a string bug it does not have.
        if "':'" in message:
            return (f"a ':' is missing at char {position} before "
                    f"{_excerpt(body[position:position + _EXCERPT_CHARS])!r} - an object member name is "
                    f"not followed by its value")
        if "','" in message:
            # Two peers adjacent, with no separator between them. Refused rather than inserted: the
            # comma is a PLACE the model left empty, and asserting the structure there is a decision
            # (_looks_like_object_member refuses the same class one branch over).
            if quote_at_error and _looks_like_object_member(body, position):
                return (f"a ',' is missing at char {position} between two object members "
                        f"({_excerpt(body[position:position + _EXCERPT_CHARS])!r}) - the repair pass "
                        f"does not insert one")
            if quote_at_error and _starts_a_separate_value(body, position):
                # agents-9tw8i: the array/string twin of the member shape. `{"tags": ["a" "b"]}` is two
                # values with no comma, and calling it an unescaped quote sends the retry hunting a
                # string bug it does not have.
                return (f"a ',' is missing at char {position} between two values "
                        f"({_excerpt(body[position:position + _EXCERPT_CHARS])!r}) - the repair pass "
                        f"does not insert one, and it refuses to escape the quote because escaping it "
                        f"would merge two values into one string")
            if not quote_at_error and not quote_before:
                return (f"a ',' is missing at char {position} between two values "
                        f"({_excerpt(body[max(position - 40, 0):position + _EXCERPT_CHARS])!r}) - the "
                        f"repair pass does not insert one")
        if quote_at_error or quote_before:
            # The same two shapes `_one_repair` escapes: the quote the decoder stopped AT, or the quote
            # just before the position it choked on (a string that ended early, then prose). Mirrored
            # here so a payload the repair declined is still NAMED as the unescaped-quote shape it is.
            where = position if quote_at_error else index
            return (f"a string contains an unescaped quote at char {where} "
                    f"({_excerpt(body[max(where - 40, 0):where + _EXCERPT_CHARS])!r}) that the repair "
                    f"pass could not escape within its bound")
    if "property name" in message:
        return (f"an object member name at char {position} is not a quoted string "
                f"({_excerpt(body[position:])!r})")
    return None
