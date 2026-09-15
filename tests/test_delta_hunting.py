"""Tests for continuous / delta hunting wiring in the orchestrator (WS8)."""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from hacking_agent.core import attack_surface as asm


def _build_orch(target="https://x.com/", mission_mode="production", db_path=None):
    from hacking_agent.cli.orchestrator import Orchestrator
    env = {"DEEPSEEK_API_KEY": "test-key", "REYNARD_EMBEDDINGS": "lexical"}
    if db_path:
        env["REYNARD_DURABLE_MEMORY"] = "1"
        env["REYNARD_MEMORY_DB"] = db_path
    else:
        env["REYNARD_DURABLE_MEMORY"] = "0"
    with patch.dict(os.environ, env, clear=False):
        return Orchestrator(target_url=target, objective="test",
                            subagents_enabled=False, max_iterations=6,
                            mission_mode=mission_mode)


class DeltaSeedingTests(unittest.TestCase):
    def test_new_asset_since_prior_gets_delta_seed(self):
        orch = _build_orch()
        try:
            # prior run knew about www.x.com
            orch.prior_surface.add_host("www.x.com", source="subfinder")
            # this run rediscovers www.x.com and finds a NEW admin subdomain
            orch.surface.add_host("www.x.com", source="subfinder")
            orch.surface.add_host("admin.x.com", source="subfinder")
            orch._sync_agenda_from_surface()
            notes = {h.vector: h.notes for h in orch.agenda.all()}
            self.assertEqual(notes.get("admin.x.com"), "seed:surface_delta")
            # the previously-known host is seeded as known surface (not delta)
            self.assertEqual(notes.get("www.x.com"), "seed:surface")
            # the new admin subdomain outranks the previously-known host
            admin_h = next(h for h in orch.agenda.all() if h.vector == "admin.x.com")
            www_h = next(h for h in orch.agenda.all() if h.vector == "www.x.com")
            self.assertGreater(admin_h.heat, www_h.heat)
        finally:
            orch.logger.close()

    def test_out_of_scope_assets_not_seeded(self):
        orch = _build_orch(target="https://x.com/")
        try:
            orch.surface.add_host("evil.com", source="subfinder")  # out of scope
            orch._sync_agenda_from_surface()
            self.assertFalse(any(h.vector == "evil.com" for h in orch.agenda.all()))
        finally:
            orch.logger.close()


class DeltaPersistenceTests(unittest.TestCase):
    def test_surface_persists_and_reloads_across_runs(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "mem.db")
        # Run 1: discover an asset and persist.
        orch1 = _build_orch(db_path=db)
        try:
            orch1.surface.add_host("api.x.com", source="subfinder")
            orch1._persist_durable()  # persists + closes durable
        finally:
            orch1.logger.close()
        # Run 2: prior surface should load api.x.com from the durable store.
        orch2 = _build_orch(db_path=db)
        try:
            orch2._rehydrate_durable()
            self.assertIsNotNone(
                next((a for a in orch2.prior_surface.assets()
                      if a.identifier == "api.x.com"), None)
            )
        finally:
            orch2.logger.close()


if __name__ == "__main__":
    unittest.main()
