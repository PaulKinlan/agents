#!/usr/bin/env python3
"""The station prompt is not in argv, and the retained copy is not world-readable (agents-pgr).

`factory` used to pass the whole prompt — up to 50 raw scanner records, credential lines
included — as a command-line argument to the adapter, and wrote prompt.txt at the process umask.
argv and a world-readable file are as exposed as an environment variable (non-negotiable #4).
The prompt now goes on stdin, and the run directory is private.
"""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

loader = importlib.machinery.SourceFileLoader("factory_cli_pgr", str(ROOT / "factory"))
spec = importlib.util.spec_from_loader("factory_cli_pgr", loader)
factory_cli = importlib.util.module_from_spec(spec)
loader.exec_module(factory_cli)

# Assembled at runtime: a literal would be reported by the repo's own secret-scan pre-pass.
KEY = "AKIA" + "IOSFODNN7EXAMPLE"


class PromptSandbox:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.target = root / "target"
        self.engine_args = root / "engine-args.log"
        self.engine_prompt = root / "engine-prompt.log"
        self.adapter_argv = root / "adapter-argv.log"
        self._build()

    def _build(self) -> None:
        (self.root / "agents" / "probe" / "scripts").mkdir(parents=True)
        (self.root / "agents" / "probe" / "agent.yaml").write_text(
            "name: probe\n"
            "class: observer\n"
            "containment: t0-readonly\n"
            "short_circuit_empty: false\n"
            "budget: {max_minutes: 1}\n",
            encoding="utf-8",
        )
        candidates = self.root / "candidates-src.json"
        candidates.write_text(json.dumps({"candidates": [{
            "rule_id": "aws-access-key",
            "path": "src/a.js",
            "line_number": 1,
            "snippet": f"const k = '{KEY}';",
        }]}), encoding="utf-8")
        (self.root / "agents" / "probe" / "scripts" / "prepass.py").write_text(
            "import json, sys\n"
            "args = sys.argv[1:]\n"
            f"payload = json.load(open(r'{candidates}'))\n"
            "json.dump(payload, open(args[args.index('--output') + 1], 'w'))\n",
            encoding="utf-8",
        )

        (self.root / "lib" / "adapters").mkdir(parents=True)
        adapter = self.root / "lib" / "adapters" / "pi.sh"
        shutil.copyfile(ROOT / "lib" / "adapters" / "pi.sh", adapter)
        adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
        for module in ("findings.py", "redaction.py", "embargo.py"):
            shutil.copyfile(ROOT / "lib" / module, self.root / "lib" / module)

        report = self.root / "report-src.json"
        report.write_text(json.dumps({"summary": "stub", "scanned_files": 1, "findings": []}),
                          encoding="utf-8")
        bindir = self.root / "bin"
        bindir.mkdir()
        stub = bindir / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            f"printf '%s' \"$*\" > '{self.engine_args}'\n"
            f"cat > '{self.engine_prompt}'\n"
            f"if [ -r /proc/$PPID/cmdline ]; then tr '\\0' ' ' < /proc/$PPID/cmdline > '{self.adapter_argv}'; fi\n"
            f"cat '{report}'\n",
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.bin = bindir

        self.target.mkdir()

    def run(self) -> Path:
        """Run one station with umask 0, so only an explicit chmod can make artifacts private."""
        env = {"PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"}
        old_umask = os.umask(0)
        try:
            with mock.patch.object(factory_cli, "FACTORY_ROOT", self.root), \
                 mock.patch.dict(os.environ, env):
                factory_cli.run_agent("probe", str(self.target), engine_arg="pi")
        finally:
            os.umask(old_umask)
        run_dir, = sorted((self.root / "runs").glob("probe-target-*"))
        return run_dir


class TestPromptExposure(unittest.TestCase):
    def test_the_prompt_is_delivered_on_stdin_and_the_run_dir_is_private(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = PromptSandbox(Path(tmpdir))
            run_dir = sandbox.run()

            prompt_file = run_dir / "prompt.txt"
            self.assertIn(KEY, prompt_file.read_text(encoding="utf-8"),
                          "the retained prompt must still be the real one")
            self.assertEqual(stat.S_IMODE(run_dir.stat().st_mode), 0o700,
                             "run artifacts hold raw scanner matches")
            self.assertEqual(stat.S_IMODE(prompt_file.stat().st_mode), 0o600,
                             "the retained prompt must not be world-readable")

            # The prompt reached the engine, which proves the stdin hop works end to end.
            self.assertIn(KEY, sandbox.engine_prompt.read_text(encoding="utf-8"))
            # ...and it is not in the engine's argv, nor in the adapter's.
            self.assertNotIn(KEY, sandbox.engine_args.read_text(encoding="utf-8"))
            if sandbox.adapter_argv.exists() and sandbox.adapter_argv.stat().st_size:
                self.assertNotIn(KEY, sandbox.adapter_argv.read_text(encoding="utf-8"),
                                 "the dispatcher must not put the prompt in argv")

    def test_an_empty_stdin_is_rejected_loudly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = PromptSandbox(Path(tmpdir))
            run_dir = sandbox.root / "run"
            res = subprocess.run(
                ["bash", str(sandbox.root / "lib" / "adapters" / "pi.sh"),
                 "probe", str(sandbox.target), str(sandbox.root), str(run_dir)],
                input="", capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 2)
            self.assertIn("empty prompt", res.stderr)


if __name__ == "__main__":
    unittest.main()
