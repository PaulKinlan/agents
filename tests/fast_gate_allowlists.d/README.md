# Fast-gate coverage allowlist fragments

Each `*.json` here is a **fragment**: a delivery drops its own file so that no
two deliveries edit one shared dict (see `agents-nerv`). The test that merges
them is `tests/test_fast_gate_consumer_coverage.py`.

## Where the reasons live

**This directory deliberately carries no reasons** (`agents-02s9`). An entry is
just the suite name; the *why* is derived when a test fails, from the gate's own
measured answer to "what do you select for this module". A prose reason used to
sit beside each entry and was **false for half the modules it described** — a
reason that cannot be written down wrong beats better prose.

The reasons, the criterion and the **exclusions** are documented in:

> **`docs/adr/0001-fast-gate-coverage-tiers.md`**
> § *The Assertion-Consumer Class: When an Importer Is Not a Consumer* (`agents-g9e2`, `agents-iwaj`)

Read that section before adding an entry or asking why a suite is excluded. It
records why the assertion-consumer class exists at all, and why
`tests/test_sinks.py`, `tests/test_factory_core.py`, `tests/test_gen_site.py` and
`tests/test_line_numbers.py` are **not** listed for `lib/line_numbers.py` — the
four exclusions most likely to be re-litigated by the next reader.

`tests/test_fast_gate_consumer_coverage.py::TestTheAllowlistPointsAtItsDocumentedReasons`
fails if this pointer rots (`agents-1mz0`).
