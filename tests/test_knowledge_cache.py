"""The local retrieval cache is data, never an executable pickle."""
import json
import pickle

import pytest

from hacking_agent.core.knowledge import Chunk, KnowledgeBase


def test_json_cache_roundtrip_and_legacy_pickle_is_never_loaded(tmp_path, monkeypatch):
    kb = KnowledgeBase(cache_dir=tmp_path, backend="lexical")
    kb._chunks = [Chunk("fixture.md", "Fixture", "Offline retrieval", 0)]
    kb._embeddings = [[1.0, 0.5]]
    kb._save_cache("lexical", "fixture")
    assert kb._cache_path("lexical", "fixture").suffix == ".json"
    restored = KnowledgeBase(cache_dir=tmp_path, backend="lexical")
    assert restored._load_cache("lexical", "fixture")
    assert restored._chunks == kb._chunks
    assert restored._embeddings == kb._embeddings
    (tmp_path / "rag_lexical_old.pkl").write_bytes(b"not trusted executable data")
    monkeypatch.setattr(pickle, "load", lambda *_: pytest.fail("pickle must never load"))
    assert not restored._load_cache("lexical", "old")


@pytest.mark.parametrize("change", [
    {"schema_version": 2}, {"chunks": [{"source": 1}]}, {"chunks": "wrong shape"},
    {"embeddings": [[float("nan")]]}, {"embeddings": [[1], [1, 2]]},
    {"embeddings": [[True]]}, {"fingerprint": "different"},
])
def test_invalid_cache_fails_closed_without_partial_state(tmp_path, change):
    kb = KnowledgeBase(cache_dir=tmp_path, backend="lexical")
    path = kb._cache_path("lexical", "fixture")
    data = {"schema_version": 1, "backend": "lexical", "fingerprint": "fixture",
            "chunks": [{"source": "fixture.md", "heading": "Fixture", "text": "text", "chunk_id": 0}],
            "embeddings": [[1.0]], **change}
    path.write_text(json.dumps(data), encoding="utf-8")
    assert not kb._load_cache("lexical", "fixture")
    assert kb._chunks == []
    assert kb._embeddings == []


def test_content_change_invalidates_cache_even_if_file_size_unchanged(tmp_path):
    source = tmp_path / "fixture.md"
    source.write_text("first", encoding="utf-8")
    kb = KnowledgeBase(methodologies_dir=tmp_path, backend="lexical")
    original = kb._fingerprint()
    source.write_text("other", encoding="utf-8")
    assert kb._fingerprint() != original
