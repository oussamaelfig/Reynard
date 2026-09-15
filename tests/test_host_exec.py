"""Tests for the opt-in host-execution backend (REYNARD_HOST_EXEC).

Default OFF so production behavior is unchanged (docker exec). When enabled,
container commands run on the host — used for local testing/validation without
the Kali container. ScopeGuard still gates every tool call."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from hacking_agent.core import tools


class HostExecTests(unittest.TestCase):
    def test_flag_defaults_off(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("REYNARD_HOST_EXEC", None)
            self.assertFalse(tools._host_exec_enabled())

    def test_flag_on(self):
        with patch.dict(os.environ, {"REYNARD_HOST_EXEC": "1"}, clear=False):
            self.assertTrue(tools._host_exec_enabled())

    def test_host_exec_runs_command_on_host(self):
        with patch.dict(os.environ, {"REYNARD_HOST_EXEC": "1"}, clear=False):
            out = tools._docker_exec("echo reynard_host_ok")
        self.assertEqual(out.get("exit_code"), 0)
        self.assertIn("reynard_host_ok", out.get("stdout", ""))

    def test_default_path_uses_docker_not_host(self):
        # With the flag off and no docker daemon, the call fails via the docker
        # path (exit_code != 0) rather than silently running on the host.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("REYNARD_HOST_EXEC", None)
            out = tools._docker_exec("echo should_not_run_on_host", timeout=5)
        self.assertNotEqual(out.get("exit_code"), 0)
        self.assertNotIn("should_not_run_on_host", out.get("stdout", ""))


if __name__ == "__main__":
    unittest.main()
