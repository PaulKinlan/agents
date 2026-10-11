#!/usr/bin/env python3
"""Make a test module independent of the OPERATOR'S HOST CONFIG (agents-21ap).

A test that reads the operator's host configuration is not a test, it is an
observation about the machine. That is not a style point: on 2026-10-11 the VM
re-provision generated ~/.config/factory/tools.pins.yaml and exported
FACTORY_TOOL_PINS from ~/.fleet/local.conf at 02:19:46Z, and from that moment the
FULL SUITE WAS RED ON EVERY TREE - including landed main - with 42 ToolPinError
and SandboxError failures whose shared message was:

    trusted tool 'pi' resolved to /tmp/.../bin/pi, not the configured path /usr/local/bin/pi

Every one of those failures was environmental. The tests were RIGHT: they plant a
fake `pi` on PATH and assert that the pin refuses it, or plant a fake bwrap and
assert the wrap refuses it. What was wrong is that they ran against whatever pins
file the operator's shell happened to export, so a gate result on a given tree
became a fact about the host rather than about the tree.

HOW TO USE THIS, in a module that exercises the pin machinery directly or spawns
something that does (the factory dispatcher, an adapter, a sandbox wrap):

    from tests import hermetic_env

    def setUpModule():
        hermetic_env.isolate_operator_config()

    def tearDownModule():
        hermetic_env.restore_operator_config()

WHAT IT DOES, AND WHY IT IS TWO THINGS RATHER THAN ONE. It removes the operator's
FACTORY_TOOL_PINS, so no test observes the host's pins file; and it SETS
FACTORY_ALLOW_UNPINNED_TOOLS=1, because these modules plant synthetic binaries and
`pi` and `bwrap` are deliberately absent from tools.yaml. Removing the ambient
input alone was tried first and made things WORSE, which is the most useful thing
learned here: test_pi_keyless_broker stayed at 2 errors with a different, more
honest message ("trusted tool 'pi' is not pinned") and test_sandbox went from
2 failures and 1 error to 4 failures and 28 errors, because those tests had been
resolving `pi` only BY ACCIDENT through the operator's host file. A module that
needs a tool resolved must either pin it itself or opt out explicitly; opting out
is what the code documents for a dev/test run, so this module installs that
opt-out and thereby makes the assumption VISIBLE instead of inherited.

WHY NOT INSTALL A PINS FILE OF OUR OWN: a pins file would have to name paths this
module cannot know (each test plants its own temp tree), and it would silently
substitute this module's opinion for the test's. The opt-out asserts the thing the
tests actually mean - "the binaries under test here are synthetic, do not
authenticate them" - which is exactly what the modules were already relying on,
just implicitly and from the wrong place.
"""

import os

#: Environment variables that let the OPERATOR'S shell, and not the tree, decide
#: what a test observes. FACTORY_TOOL_PINS is the one that broke the suite on
#: 2026-10-11; FACTORY_ALLOW_UNPINNED_TOOLS is included because it has the same
#: property in the other direction - set in a developer's shell it could turn a pin
#: refusal into a success and mask a real regression in the pin boundary.
OPERATOR_CONFIG_VARS = ("FACTORY_TOOL_PINS", "FACTORY_ALLOW_UNPINNED_TOOLS")

#: Set by isolate_operator_config() so restore_operator_config() puts back exactly
#: what was there, including the "was absent" case, and so a module that calls
#: isolate twice does not lose the original on the second call.
_SAVED = None


def isolate_operator_config():
    """Establish a DETERMINISTIC tool-pin environment for the duration of a module.

    Removes the operator's FACTORY_TOOL_PINS and sets FACTORY_ALLOW_UNPINNED_TOOLS=1,
    the documented dev/test opt-out, so the module's synthetic binaries resolve
    without the host file being involved. Returns the values it removed. Idempotent:
    the FIRST call records the real environment, later calls do not overwrite it.
    """
    global _SAVED
    if _SAVED is None:
        _SAVED = {name: os.environ.get(name) for name in OPERATOR_CONFIG_VARS}
    for name in OPERATOR_CONFIG_VARS:
        os.environ.pop(name, None)
    os.environ["FACTORY_ALLOW_UNPINNED_TOOLS"] = "1"
    return dict(_SAVED)


def restore_operator_config():
    """Put back exactly what isolate_operator_config() removed, or clear it again.

    Distinguishes "was unset" from "was set to an empty string" rather than treating
    both as absent, because a test run under the second condition is a different
    environment from one under the first and this module's whole job is to not
    quietly conflate environment states. It also removes the opt-out this module
    installs, so a module using it cannot leak that setting into the rest of a run.
    """
    global _SAVED
    if _SAVED is None:
        return
    for name, value in _SAVED.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
    _SAVED = None
