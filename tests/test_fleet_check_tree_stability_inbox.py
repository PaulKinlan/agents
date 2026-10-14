"""agents-97kx: a fleet-check fixture may simulate a POST, never deliver one.

The live fleet test is delivered as a patch, not installed by this project. Extract
its *resulting* curl stand-in from that patch so the regression exercises the
bytes we ship without depending on another repo, host inbox, or hub generation.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import subprocess
import tempfile
import threading
import unittest


PATCH = Path(__file__).resolve().parents[1] / "patches/fleet-check-tree-stability-inbox.patch"


def resulting_curl_standin(patch: str) -> str:
    """Decode unified-diff result lines only, from the stand-in's here-document."""
    lines = patch.splitlines()
    start = next(i for i, line in enumerate(lines)
                 if line[1:] == "cat > \"$ROOT/bin/curl\" <<'STUB'" and line[:1] in " +")
    result = []
    for line in lines[start + 1:]:
        if line.startswith(("-", "@@ ")):
            continue
        if line[:1] not in " +":
            raise AssertionError("curl stand-in escaped its diff hunk")
        value = line[1:]
        if value == "STUB":
            return "\n".join(result) + "\n"
        result.append(value)
    raise AssertionError("curl stand-in terminator missing from delivered patch")


class PrivateInbox(BaseHTTPRequestHandler):
    captured = []

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.captured.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_args):
        pass


class TestFleetTreeStabilityFixtureCannotNotify(unittest.TestCase):
    def test_synthetic_post_does_not_leave_standin(self):
        patch = PATCH.read_text()
        # Defence in depth: a future runner bypassing PATH cannot inherit the
        # live lane or target the live default port. The runner requires a lane,
        # so the fixture replaces it with a synthetic one rather than unsetting
        # it for the nested invocation (which would refuse before arm 7 runs).
        self.assertIn("+unset FLEET_LANE", patch)
        self.assertIn("+export FLEET_LANE=arx8-test", patch)
        self.assertIn("+export FLEET_INBOX_PORT=9", patch)
        script = resulting_curl_standin(patch)
        self.assertIn('FLEET_CHECK_TEST_HOLD', script)
        self.assertNotIn("/usr/bin/curl", script)
        self.assertNotIn("exec ", script)

        PrivateInbox.captured = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), PrivateInbox)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                stub = Path(tmp, "curl")
                stub.write_text(script)
                stub.chmod(0o700)
                url = f"http://127.0.0.1:{server.server_address[1]}/msg"
                env = dict(os.environ)
                env.pop("FLEET_CHECK_TEST_HOLD", None)
                argv = [str(stub), "-s", "-f", "-m", "2", "-X", "POST",
                        "-H", "content-type: application/json", "--data-binary", "{}", url]

                # Prove the listener AND the counter work: the pristine fixture's
                # forwarding line is the mutant that sends one real private POST.
                mutant = script.rsplit("exit 0", 1)[0] + 'exec /usr/bin/curl "$@"\n'
                stub.write_text(mutant)
                self.assertEqual(subprocess.run(argv, env=env, capture_output=True,
                                                timeout=4).returncode, 0)
                self.assertEqual(PrivateInbox.captured, ["/msg"])
                PrivateInbox.captured.clear()

                # The delivered stand-in consumes both ordinary and held POSTs.
                stub.write_text(script)
                self.assertEqual(subprocess.run(argv, env=env, capture_output=True,
                                                timeout=4).returncode, 0)
                held = Path(tmp, "released")
                held.touch()
                env["FLEET_CHECK_TEST_HOLD"] = str(held)
                self.assertEqual(subprocess.run(argv, env=env, capture_output=True,
                                                timeout=4).returncode, 0)
                self.assertEqual(PrivateInbox.captured, [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
