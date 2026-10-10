#!/bin/bash
export PATH="/tmp/fake_git:$PATH"
export FACTORY_TOOL_PINS="/tmp/attack_d/old.tools.pins.yaml" # or unpinned tools allowed
export FACTORY_ALLOW_UNSANDBOXED=1
python3 factory run docs-write --target . --engine pi 2>&1 | grep PWNED_GIT || true
