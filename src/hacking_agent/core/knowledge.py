"""
=============================================================================
Reynard — Local RAG over methodologies/
=============================================================================
Cheap/local models cannot rely on parametric knowledge, so the methodology
corpus is chunked, embedded with a LOCAL zero-API-cost backend, and retrieved
per hypothesis/phase. Three backends, auto-detected in order of quality:

  1. sentence-transformers  (all-MiniLM-L6-v2)   — best, fully local
  2. ollama embeddings      (nomic-embed-text)   — local daemon, no PyPI dep
  3. lexical (BM25)         — pure-Python, always available

Selection is overridable via REYNARD_EMBEDDINGS=sentence-transformers|ollama|
lexical. All heavyweight imports are guarded so the base install keeps working
and the feature NEVER hard-fails on an offline/cheap setup.

The index is cached on disk and rebuilt only when the methodology files change
(content hash + mtime fingerprint).
=============================================================================
"""
from __future__ import annotations

import hashlib
import math
import os
import pickle
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hacking_agent.core.paths import LOG_DIR, METHODOLOGIES_DIR

_TOKEN_RE = re.compile(r"[a-z0-9_]+")
_HEADING_RE = re.compile(r"^(#{1,4})\s+(.*)$")


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


# =============================================================================
# Chunk types
# =============================================================================

@dataclass
class Chunk:
    """A retrievable slice of a methodology file, scoped to a heading."""
    source: str
    heading: str
    text: str
    chunk_id: int = 0


@dataclass
class RetrievedChunk:
    """A chunk plus its relevance score for a given query."""
    source: str
    heading: str
    text: str
    score: float

    def render(self) -> str:
        return f"### {self.heading}  ({self.source})\n{self.text.strip()}"


# =============================================================================
# Chunking
# =============================================================================

_MAX_CHUNK_CHARS = 1600


def _split_markdown(source: str, content: str) -> list[Chunk]:
    """Split a markdown file into heading-scoped chunks.

    Sections are cut on `##`/`###`/`####` headings; long sections are further
    split on paragraph boundaries so a single chunk stays prompt-friendly.
    """
    chunks: list[Chunk] = []
    current_heading = source.replace(".md", "")
    buf: list[str] = []

    def flush(heading: str, lines: list[str]) -> None:
        body = "\n".join(lines).strip()
        if not body:
            return
        if len(body) <= _MAX_CHUNK_CHARS:
            chunks.append(Chunk(source=source, heading=heading, text=body))
            return
        # Further split oversized sections on blank lines, greedily packing.
        para: list[str] = []
        size = 0
        for para_block in re.split(r"\n\s*\n", body):
            block = para_block.strip()
            if not block:
                continue
            if size + len(block) > _MAX_CHUNK_CHARS and para:
                chunks.append(Chunk(source=source, heading=heading,
                                    text="\n\n".join(para)))
                para, size = [], 0
            para.append(block)
            size += len(block)
        if para:
            chunks.append(Chunk(source=source, heading=heading,
                                text="\n\n".join(para)))

    for line in content.splitlines():
        m = _HEADING_RE.match(line)
        if m and m.group(1) in ("##", "###", "####"):
            flush(current_heading, buf)
            current_heading = m.group(2).strip()
            buf = []
        else:
            buf.append(line)
    flush(current_heading, buf)

    for i, c in enumerate(chunks):
        c.chunk_id = i
    return chunks


# =============================================================================
# Embedding backends
# =============================================================================

class _Backend:
    """Base class. name is used for cache invalidation and diagnostics."""
    name = "base"
    is_vector = False

    def embed(self, texts: list[str]) -> list[list[float]]:  # pragma: no cover
        raise NotImplementedError


class _SentenceTransformerBackend(_Backend):
    name = "sentence-transformers"
    is_vector = True

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        from sentence_transformers import SentenceTransformer  # type: ignore

        self._model = SentenceTransformer(model_name)

    def embed(self, texts: list[str]) -> list[list[float]]:
        vecs = self._model.encode(texts, normalize_embeddings=True,
                                  show_progress_bar=False)
        return [list(map(float, v)) for v in vecs]


class _OllamaBackend(_Backend):
    name = "ollama"
    is_vector = True

    def __init__(self, model_name: str = "nomic-embed-text",
                 base_url: str | None = None):
        import httpx  # guarded — httpx is a base dep but keep symmetry

        self._httpx = httpx
        self._model = os.getenv("REYNARD_EMBEDDINGS_MODEL", model_name)
        self._base = (base_url or os.getenv("OLLAMA_BASE_URL")
                      or "http://localhost:11434").rstrip("/")
        # Fail fast if the daemon is unreachable so auto-detect can fall back.
        resp = self._httpx.get(f"{self._base}/api/tags", timeout=3.0)
        resp.raise_for_status()

    def _embed_one(self, text: str) -> list[float]:
        resp = self._httpx.post(
            f"{self._base}/api/embeddings",
            json={"model": self._model, "prompt": text},
            timeout=30.0,
        )
        resp.raise_for_status()
        vec = resp.json().get("embedding") or []
        return [float(x) for x in vec]

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_one(t) for t in texts]


class _LexicalBackend(_Backend):
    """Pure-Python BM25 — no embeddings, scores queries directly at retrieval."""
    name = "lexical"
    is_vector = False

    def embed(self, texts: list[str]) -> list[list[float]]:
        return []


def _select_backend(preference: str | None) -> _Backend:
    """Resolve the embedding backend with graceful auto-detection."""
    order: list[str]
    pref = (preference or os.getenv("REYNARD_EMBEDDINGS") or "auto").lower()
    if pref in ("sentence-transformers", "sentence_transformers", "st"):
        order = ["sentence-transformers"]
    elif pref == "ollama":
        order = ["ollama"]
    elif pref == "lexical":
        order = ["lexical"]
    else:
        order = ["sentence-transformers", "ollama", "lexical"]

    for name in order:
        try:
            if name == "sentence-transformers":
                return _SentenceTransformerBackend()
            if name == "ollama":
                return _OllamaBackend()
            if name == "lexical":
                return _LexicalBackend()
        except Exception:
            continue
    return _LexicalBackend()


# =============================================================================
# Vector math (numpy if available, pure-python fallback)
# =============================================================================

def _cosine(a: list[float], b: list[float]) -> float:
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na <= 0.0 or nb <= 0.0:
        return 0.0
    return dot / (math.sqrt(na) * math.sqrt(nb))


# =============================================================================
# BM25 (lexical fallback)
# =============================================================================

class _BM25:
    def __init__(self, docs: list[list[str]], k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.docs = docs
        self.N = len(docs)
        self.doc_len = [len(d) for d in docs]
        self.avgdl = (sum(self.doc_len) / self.N) if self.N else 0.0
        self.df: dict[str, int] = {}
        self.tf: list[dict[str, int]] = []
        for d in docs:
            seen: dict[str, int] = {}
            for tok in d:
                seen[tok] = seen.get(tok, 0) + 1
            self.tf.append(seen)
            for tok in seen:
                self.df[tok] = self.df.get(tok, 0) + 1

    def _idf(self, term: str) -> float:
        n = self.df.get(term, 0)
        return math.log(1 + (self.N - n + 0.5) / (n + 0.5))

    def scores(self, query: list[str]) -> list[float]:
        out = [0.0] * self.N
        for i in range(self.N):
            dl = self.doc_len[i] or 1
            tf = self.tf[i]
            s = 0.0
            for term in query:
                f = tf.get(term, 0)
                if f == 0:
                    continue
                idf = self._idf(term)
                denom = f + self.k1 * (1 - self.b + self.b * dl / (self.avgdl or 1))
                s += idf * (f * (self.k1 + 1)) / denom
            out[i] = s
        return out


# =============================================================================
# KnowledgeBase
# =============================================================================

class KnowledgeBase:
    """Chunk + embed + retrieve over the methodology corpus.

    Thread-safe lazy build. Retrieval degrades gracefully: any backend failure
    falls back to lexical BM25 so this never raises to callers.
    """

    def __init__(self, methodologies_dir: Path | None = None,
                 cache_dir: Path | None = None,
                 backend: str | None = None):
        self.dir = Path(methodologies_dir or METHODOLOGIES_DIR)
        self.cache_dir = Path(cache_dir or (LOG_DIR / ".rag_cache"))
        self._backend_pref = backend
        self._lock = threading.RLock()
        self._built = False
        self._backend: _Backend | None = None
        self._chunks: list[Chunk] = []
        self._embeddings: list[list[float]] = []
        self._bm25: _BM25 | None = None

    # ---- fingerprint / cache -------------------------------------------

    def _fingerprint(self) -> str:
        h = hashlib.sha256()
        if self.dir.is_dir():
            for path in sorted(self.dir.glob("*.md")):
                try:
                    stat = path.stat()
                    h.update(path.name.encode())
                    h.update(str(stat.st_size).encode())
                    h.update(str(int(stat.st_mtime)).encode())
                except OSError:
                    continue
        return h.hexdigest()[:16]

    def _cache_path(self, backend_name: str, fp: str) -> Path:
        return self.cache_dir / f"rag_{backend_name}_{fp}.pkl"

    def _load_cache(self, backend_name: str, fp: str) -> bool:
        path = self._cache_path(backend_name, fp)
        if not path.exists():
            return False
        try:
            with open(path, "rb") as fh:
                data = pickle.load(fh)
            if data.get("fingerprint") != fp or data.get("backend") != backend_name:
                return False
            self._chunks = data["chunks"]
            self._embeddings = data.get("embeddings") or []
            return True
        except Exception:
            return False

    def _save_cache(self, backend_name: str, fp: str) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            path = self._cache_path(backend_name, fp)
            with open(path, "wb") as fh:
                pickle.dump({
                    "fingerprint": fp,
                    "backend": backend_name,
                    "chunks": self._chunks,
                    "embeddings": self._embeddings,
                }, fh)
        except Exception:
            pass

    # ---- build ----------------------------------------------------------

    def _read_chunks(self) -> list[Chunk]:
        chunks: list[Chunk] = []
        if not self.dir.is_dir():
            return chunks
        for path in sorted(self.dir.glob("*.md")):
            try:
                content = path.read_text(encoding="utf-8")
            except OSError:
                continue
            chunks.extend(_split_markdown(path.name, content))
        for i, c in enumerate(chunks):
            c.chunk_id = i
        return chunks

    def build(self, force: bool = False) -> None:
        with self._lock:
            if self._built and not force:
                return
            self._backend = _select_backend(self._backend_pref)
            fp = self._fingerprint()
            loaded = False
            if not force:
                loaded = self._load_cache(self._backend.name, fp)
            if not loaded:
                self._chunks = self._read_chunks()
                self._embeddings = []
                if self._backend.is_vector and self._chunks:
                    try:
                        self._embeddings = self._backend.embed(
                            [c.text for c in self._chunks]
                        )
                    except Exception:
                        # Vector backend broke mid-build → drop to lexical.
                        self._backend = _LexicalBackend()
                        self._embeddings = []
                self._save_cache(self._backend.name, fp)

            if not self._backend.is_vector or not self._embeddings:
                self._bm25 = _BM25([_tokenize(c.text + " " + c.heading)
                                    for c in self._chunks])
            self._built = True

    # ---- retrieve -------------------------------------------------------

    def retrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        """Return the top-k most relevant chunks for a query."""
        if not query or not query.strip():
            return []
        try:
            self.build()
        except Exception:
            return []
        with self._lock:
            if not self._chunks:
                return []
            backend = self._backend
            if backend is not None and backend.is_vector and self._embeddings:
                try:
                    qvec = backend.embed([query])[0]
                    scored = [
                        (_cosine(qvec, emb), i)
                        for i, emb in enumerate(self._embeddings)
                    ]
                except Exception:
                    scored = self._lexical_scores(query)
            else:
                scored = self._lexical_scores(query)

            scored.sort(key=lambda t: t[0], reverse=True)
            out: list[RetrievedChunk] = []
            for score, idx in scored[:k]:
                if score <= 0:
                    continue
                c = self._chunks[idx]
                out.append(RetrievedChunk(
                    source=c.source, heading=c.heading,
                    text=c.text, score=round(float(score), 4),
                ))
            return out

    def _lexical_scores(self, query: str) -> list[tuple[float, int]]:
        if self._bm25 is None:
            self._bm25 = _BM25([_tokenize(c.text + " " + c.heading)
                                for c in self._chunks])
        raw = self._bm25.scores(_tokenize(query))
        return [(s, i) for i, s in enumerate(raw)]

    def backend_name(self) -> str:
        if self._backend is None:
            try:
                self.build()
            except Exception:
                return "unavailable"
        return self._backend.name if self._backend else "unavailable"

    def chunk_count(self) -> int:
        if not self._built:
            try:
                self.build()
            except Exception:
                return 0
        return len(self._chunks)


# =============================================================================
# Module-level singleton + convenience API
# =============================================================================

_KB_LOCK = threading.Lock()
_KB: KnowledgeBase | None = None


def get_knowledge_base() -> KnowledgeBase:
    global _KB
    with _KB_LOCK:
        if _KB is None:
            _KB = KnowledgeBase()
        return _KB


def retrieve(query: str, k: int = 5) -> list[RetrievedChunk]:
    """Top-level convenience: retrieve top-k chunks from the shared index."""
    try:
        return get_knowledge_base().retrieve(query, k=k)
    except Exception:
        return []


def retrieve_context(query: str, k: int = 5, max_chars: int = 6000) -> str:
    """Render top-k retrieved chunks as a single prompt-injectable block."""
    chunks = retrieve(query, k=k)
    if not chunks:
        return ""
    parts: list[str] = ["# RETRIEVED METHODOLOGY (RAG)"]
    size = 0
    for c in chunks:
        block = c.render()
        if size + len(block) > max_chars:
            break
        parts.append(block)
        size += len(block)
    return "\n\n".join(parts)
