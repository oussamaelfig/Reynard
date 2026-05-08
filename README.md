# Autonomous Hacking Agent

Autonomous CTF and authorized web security testing agent with a Kali/Lightpanda tool runtime, structured memory, multi-agent orchestration, and multi-provider LLM support.

Use this only on systems you own, CTF labs, or targets where you have explicit authorization.

## Project Structure

```text
hacking-agent/
|-- agent.py                 # Compatibility launcher for single-agent CLI
|-- orchestrator.py          # Compatibility launcher for multi-agent CLI
|-- pyproject.toml           # Package metadata and console scripts
|-- src/hacking_agent/
|   |-- cli/                 # CLI entry points
|   |-- core/                # memory, providers, schemas, tools, strategy
|   |-- agents/              # coordinator, recon, analyst, exploitation, validator, reporter
|   `-- integrations/        # Burp and Caido clients
|-- methodologies/           # Bug-class playbooks mounted to /data/methodologies
|-- tests/fixtures/          # Test fixtures and sample HTML
|-- logs/                    # Session logs, ignored by git
|-- Dockerfile               # Kali Linux base image with Lightpanda and tools
|-- docker-compose.yml       # Container orchestration
|-- requirements.txt         # Python dependencies
|-- .env.example             # Safe environment template
`-- .env                     # Local secrets, ignored by git
```

## Quick Start

```bash
cp .env.example .env
# edit .env with one provider key

python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

docker compose build
docker compose up -d

python orchestrator.py "Solve this authorized CTF/lab target: https://TARGET"
```

The root `agent.py` and `orchestrator.py` files are launchers. The implementation lives under `src/hacking_agent`.

## LLM Providers

The orchestrator supports provider presets:

| Provider | Required key env | Notes |
|---|---|---|
| `deepseek` | `DEEPSEEK_API_KEY` | OpenAI-compatible DeepSeek API |
| `openai` or `gpt` | `OPENAI_API_KEY` | OpenAI-compatible GPT models |
| `anthropic` or `claude` | `ANTHROPIC_API_KEY` | Claude Messages API with typed tool output |
| `qwen` or `dashscope` | `QWEN_API_KEY` or `DASHSCOPE_API_KEY` | OpenAI-compatible Qwen/DashScope |
| `local` | optional | OpenAI-compatible local server at `http://localhost:8000/v1` |
| `ollama` | optional | OpenAI-compatible Ollama at `http://localhost:11434/v1` |
| `openai-compatible` | `LLM_DEFAULT_API_KEY` | Any custom compatible gateway via `LLM_DEFAULT_BASE_URL` |

Example:

```env
LLM_DEFAULT_PROVIDER=deepseek
LLM_DEFAULT_MODEL=deepseek-chat
DEEPSEEK_API_KEY=sk-your-key

# Per-agent overrides are optional:
LLM_ANALYST_PROVIDER=openai
LLM_ANALYST_MODEL=gpt-your-model
OPENAI_API_KEY=sk-your-openai-key

LLM_EXPLOITATION_PROVIDER=qwen
LLM_EXPLOITATION_MODEL=qwen-plus
QWEN_API_KEY=sk-your-qwen-key
```

Reasoning controls:

```env
LLM_DEFAULT_REASONING_EFFORT=high
LLM_ANALYST_REASONING_EFFORT=high
LLM_EXPLOITATION_REASONING_EFFORT=high
LLM_COORDINATOR_THINKING=true
LLM_COORDINATOR_THINKING_BUDGET=8000
LLM_DEFAULT_ENABLE_THINKING_PARAM=false
```

Unsupported reasoning parameters are downgraded automatically at runtime.

## Agent Strengths

- Multi-agent loop: coordinator, recon, analyst, exploitation, validator, reporter.
- Persistent knowledge graph with pheromone ranking for hot leads.
- Payload deduplication and failed-attempt memory to avoid repeating exact dead ends.
- Tool budgets and state-machine transitions to prevent freeform loops.
- Automatic HTTP/browser response analysis for reflection, encoding, WAF, AngularJS, CSP, forms, and lab-solved signals.
- OOB, differential, multi-session, Burp MCP, and Caido Cloud API tools.
- Validator agent replays PoCs and demotes weak findings.

## Available Tools

| Tool | Description |
|---|---|
| `run_shell` | Execute commands inside the Kali container |
| `read_file`, `write_file`, `list_dir` | File operations inside the container |
| `http_request` | HTTP via curl with persistent cookies |
| `browser_navigate`, `browser_execute_js`, `browser_interact` | Lightpanda browser automation |
| `analyze_response` | Manual response analysis |
| `oob_get_domain`, `oob_poll` | Blind vulnerability callbacks |
| `capture_baseline`, `diff_against_baseline` | Differential analysis |
| `swap_session`, `list_sessions` | Multi-identity auth testing |
| `nuclei_scan`, `extract_js_endpoints`, `discover_apis` | Recon expansion |
| `caido_cloud_api`, `caido_cloud_request` | Caido Cloud API integration |
| Burp MCP tools | Burp traffic, scanner, collaborator, repeater, intruder |

## Caido

Configure:

```env
CAIDO_PAT=caido_YOUR_PERSONAL_ACCESS_TOKEN
CAIDO_API_BASE_URL=https://api.caido.io
```

Supported high-level Caido operations include user, team, invitations, subscription, users, workspace, voucher claims, and PAT lifecycle helpers. `caido_cloud_request` is available for new Cloud API paths.

## Logs

Every run writes session logs under `logs/`. Memory state includes known facts, payload history, failed attempts, KG entities, and relationships.
