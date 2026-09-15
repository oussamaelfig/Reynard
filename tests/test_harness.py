"""Tests for harness simplification (WS12): lean single-agent methodology prompt."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from hacking_agent.cli import agent as agent_mod
from hacking_agent.cli.agent import HackingAgent, _methodology_index, load_methodologies
from hacking_agent.core.memory import AgentMemory


class MethodologyPromptTests(unittest.TestCase):
    def test_index_is_much_smaller_than_full_dump(self):
        index = _methodology_index()
        full = load_methodologies()
        # The compact index lists playbook names; the full dump pastes every file.
        self.assertTrue(index)
        self.assertLess(len(index), len(full) / 5)

    def test_relevant_methodology_uses_rag_when_available(self):
        a = object.__new__(HackingAgent)  # avoid heavy __init__ (no API client)
        a.memory = AgentMemory(target_url="https://app.example.com/")
        a.memory.current_hypothesis = "reflected xss in q parameter"
        with patch("hacking_agent.core.knowledge.retrieve_context",
                   return_value="# RETRIEVED METHODOLOGY (RAG)\nxss stuff"):
            out = a._relevant_methodology()
        self.assertIn("RAG", out)

    def test_relevant_methodology_falls_back_to_compact_index(self):
        a = object.__new__(HackingAgent)
        a.memory = AgentMemory(target_url="https://app.example.com/")
        with patch("hacking_agent.core.knowledge.retrieve_context", return_value=""):
            out = a._relevant_methodology()
        # Falls back to the compact index, NOT the full ~168KB dump.
        self.assertLess(len(out), len(load_methodologies()) / 5)


if __name__ == "__main__":
    unittest.main()
