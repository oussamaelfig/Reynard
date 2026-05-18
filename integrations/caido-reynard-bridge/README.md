# Reynard Caido Bridge

Backend-only Caido plugin that exposes a local HTTP bridge for Reynard/Hacking Agent.

It listens on:

```text
http://127.0.0.1:17650
```

Build:

```powershell
pnpm install
pnpm build
```

Install the generated package in Caido:

```text
dist/plugin_package.zip
```

After installing/enabling the plugin, the project check should return `ok: true`:

```powershell
$env:PYTHONPATH = "src"
python -c "from hacking_agent.integrations.caido_local import CaidoLocalBridgeClient; import json; print(json.dumps(CaidoLocalBridgeClient(timeout=2).status(), indent=2))"
```
