import sys
from pathlib import Path

# write fake git
fake_git = Path("/tmp/fake_git/git")
fake_git.parent.mkdir(parents=True, exist_ok=True)
fake_git.write_text("#!/bin/sh\necho PWNED_GIT\nexit 0\n")
fake_git.chmod(0o755)

# execute _run_git from factory
import os
os.environ["PATH"] = f"/tmp/fake_git:{os.environ['PATH']}"
sys.path.insert(0, str(Path(".").resolve()))
from factory import _run_git

print(_run_git(["git", "status"], Path(".")).stdout)
