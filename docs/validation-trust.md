# Validation evidence trust boundary

Customer reports use reportability schema v2. A finding is eligible for export
only when all of these layers verify:

1. The tool executor captured complete request/response observations and
   generated immutable capture/context IDs and content hashes.
2. A deterministic executor adapter produced a supported structured effect.
   Model notes, outcomes, context IDs, behavioral signals, and proof metadata
   are never used as positive or control evidence.
3. Two separately signed effect captures and one separately signed matched
   control form a valid protocol receipt.
4. Required artifacts are stored beneath the authority's content-addressed
   artifact root and verify as regular, non-symlink files with the signed path,
   kind, media type, size, SHA-256 digest, producer, capture time, and run
   binding.
5. The complete customer finding projection and the enclosing report document
   have valid HMAC-SHA256 receipts. Stored reports are re-verified at every
   Markdown, JSON, API, submission, aggregate, and count boundary.

## Key lifecycle

On first signing use, Reynard creates:

`~/.local/state/reynard/validation/authority.key`

The directory and key are created with modes `0700` and `0600` on platforms
that support POSIX permissions. Set `REYNARD_VALIDATION_STATE_DIR` to relocate
the state directory. Operators may instead inject a 32-byte-or-longer hex or
URL-safe base64 key with `REYNARD_VALIDATION_HMAC_KEY`.

Do not put the key in a report, prompt, repository, or model-accessible tool
result. Back up the key separately if old reports must remain locally
verifiable. Intentional rotation or key loss makes old reports fail closed.
Reports moved to another host require the matching authority key and artifact
store; otherwise they remain useful as untrusted records but yield zero
confirmed findings.

Artifacts live under the same state directory in `artifacts/<run-id>/`, using
content-addressed filenames. Their signed manifests, not path strings, are
embedded in evidence.

## Guarantees and non-guarantees

The HMAC proves that the local Reynard control plane holding the key issued the
receipt and that signed bytes, bindings, and projections were not changed
afterward. It prevents model output or edited report JSON from self-attesting.
It does not prove that a remote system is honest, that a deterministic detector
is semantically perfect, or that every real vulnerability will be supported.

This design does not defend against a compromised local Reynard process,
malicious code running as the same OS account, theft of the authority key, or
an operator deliberately minting false receipts. It reduces false-positive
promotion paths; it does not promise zero false positives. Unsupported effect
forms and missing adapters are intentionally suppressed, which can create false
negatives.
