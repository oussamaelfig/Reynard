"""
Reynard run harness — a single-operator local web console.

A thin control plane over the existing engagement engine: submit a target +
scope + description via a form, execute each run as an ISOLATED subprocess
(Reynard uses process-global singletons, so runs must not share a process),
watch live progress over SSE, and read the evidence-backed report. It does not
change the agent/reasoning architecture.
"""
