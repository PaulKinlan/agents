#!/bin/bash
export PATH="/tmp/fake_git:$PATH"
export FACTORY_ALLOW_UNSANDBOXED=1
python3 factory run vuln-discovery --target . --engine pi 2>&1 | grep PWNED_GIT || true
