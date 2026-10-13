## `fleet-coverage-oracle-narrow-subprocess-source.patch` (agents-hbz3)

**Applies to** `~/fleet/remote/check-coverage.py` at 40977 bytes, sha256 d60e9ad23d460ac1..., mtime 2026-10-12 19:42.
A hub delivery, like `fleet-heavy-holder-identity.patch`: the file lives in the fleet tree, which a
project VM cannot write, so the measurement and the patch are produced here and the hub applies it.

### What the fourth source is, and why it exists

`find_candidate_tests_for_file` (L559) builds its candidate set from FOUR sources, not one: project
contract files; AST package imports; `has_import_reference`; and a **subprocess/CLI-invocation pattern**.
The fourth is there for a real reason and must stay: **a suite that runs `lib/x.py` as a command consumes
it exactly as an importer does**, and nothing else in the oracle would see that channel. This patch
NARROWS it. It does not delete it.

Only `has_import_reference` is mirrored on the project side (`tests/test_fast_gate_consumer_coverage.py`,
`_importing_suites`, calibrated against this oracle in `agents-pdth`), which is why the oracle's published
omitted list and `pdth`'s allowlist cannot agree: four sources upstream, one mirrored downstream. And
because `pdth`'s staleness guard checks entries against the mirrored rule, no allowlist entry can absorb
the difference - the oracle is the outlier, not the pin.

### The defect, measured

A `lib/sandbox.py` change was published with 19 omitted suites, and 5 of them fail the oracle's own
import rule. Applying the pattern to every suite, the over-inclusion has two distinct causes:

1. **Unqualified call names.** The alternation is `(?:subprocess|Popen|exec|spawn|run|fork|call|check_output|system)`,
   so an ordinary METHOD named `run` matches. Four of the five matched the literal text `run(self, sandbox` -
   a test helper taking a `sandbox` argument, not a process being launched.
2. **No word boundary around the stem.** `test_hermetic_env.py` was published as consuming
   `lib/sandbox.py` because its suite-discovery pattern is `-p test_sandbox`, inside a genuine
   `subprocess.run` that runs discovery. `_` counts as a word character, so `\b` fixes it without
   breaking a real `"sandbox"` argument.

Generalised over every module `pdth` allowlists: **8 phantom entries across 2 modules** (`sandbox` 5,
`findings` 3 - the latter matching `finding` inside a longer parameter name).

### The change

* Call names are qualified: `subprocess.(run|Popen|call|check_output|check_call|getoutput)` or
  `os.(system|popen|spawn*|exec*)`, so a bare method call cannot match.
* The file and stem branches are anchored with `\b`, so a longer identifier containing the stem stops
  matching while a real argument still does.

### Verification, both directions

Four things were asked for, and the third is the one that matters for a narrowing:

| # | property | result |
| --- | --- | --- |
| 1 | the 8 phantoms disappear | **8 before, 0 after** - `sandbox` 5 (test_hermetic_env, test_path_security, test_pr_fixer_prepass, test_prepass_pin_boundary, test_vuln_verify_prepass) and `findings` 3, all gone, none still matching |
| 2 | a GENUINE consumer is still found | a suite running `[sys.executable, "lib/sandbox.py", "--check"]` matches before AND after; same for `-m lib.findings`; and `Popen(["python3", "lib/<m>.py"])` matches before AND after |
| 3 | the discovery pattern is not an invocation | `-p test_sandbox*` inside a real `subprocess.run`: matched before, **does not match after**. The method-call case `run(self, sandbox` likewise |
| 4 | the mirror and the oracle still agree | the import rule is untouched and the oracle keeps it unconditionally, so its candidate set still contains every suite `has_import_reference` accepts. **This is a structural argument rather than a measurement** - the import branch is not edited - and it is labelled as one rather than dressed up as a run. |

### What is NOT claimed

That the oracle has no other over-inclusion. The candidate set has four sources and only the fourth was
examined here, because that is what the omitted list for `lib/sandbox.py` exercised. The other three are
recorded as unexamined rather than assumed sound.
