"""UTC timestamps keep the legacy wire format without deprecated constructors."""
from datetime import datetime, timezone
import json
import warnings

from hacking_agent.core.attack_surface import Asset, Observation, Provenance
from hacking_agent.core.cleanup import CleanupEntry
from hacking_agent.core.differ import BaselineStore
from hacking_agent.core.durable import _now as durable_now
from hacking_agent.core.evidence_bundle import EvidenceBundle, SanitizedExchange
from hacking_agent.core.memory import Entity, FailureRecord
from hacking_agent.core.schemas import PoC, ReporterOutput
from hacking_agent.integrations.external.base import _now_iso as external_now


def test_common_timestamps_remain_naive_utc_parseable_and_legacy_comparable():
    before = datetime.now(timezone.utc).replace(tzinfo=None)
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        bundle = EvidenceBundle(id="timestamp-fixture")
        exchange = SanitizedExchange.build(
            url="https://fixture.example.test/", request="GET /", response="HTTP/1.1 200 OK",
        )
        bundle.add_test(exchange)
        timestamps = [
            Entity(id="target:fixture", type="Target").created_at,
            FailureRecord("fp", "fixture_tool", "{}", "recon", "failed", "retry", 1).created_at,
            PoC(payload="fixture", verdict="failure").timestamp,
            ReporterOutput(target_url="https://fixture.example.test/").generated_at,
            CleanupEntry(fn=lambda: None, description="fixture cleanup").registered_at,
            Asset(kind="host", identifier="fixture.example.test").first_seen,
            Provenance(source="fixture").at,
            Observation(id="fixture", category="note", summary="fixture").at,
            BaselineStore().capture("fixture", "HTTP/1.1 200 OK\n\nfixture").captured_at,
            exchange.to_dict()["timestamp"], bundle.created_at, bundle.updated_at,
            durable_now(), external_now(),
        ]
        serialized = json.loads(json.dumps(bundle.to_dict()))
        restored = EvidenceBundle.from_dict(serialized)
    after = datetime.now(timezone.utc).replace(tzinfo=None)
    legacy = datetime.fromisoformat("2000-01-01T00:00:00.000000")
    for value in timestamps:
        parsed = datetime.fromisoformat(value)
        assert parsed.tzinfo is None, "Changing offsets would break legacy naive/aware arithmetic"
        assert before <= parsed <= after
        assert (parsed - legacy).total_seconds() > 0
    assert restored.created_at == bundle.created_at
    assert restored.updated_at == bundle.updated_at
    assert restored.test_exchanges[0].timestamp == exchange.timestamp
