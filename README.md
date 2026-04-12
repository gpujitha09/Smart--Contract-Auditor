---
title: Smart Contract Auditor
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_file: server/app.py
pinned: false
---

# Smart Contract Auditor Environment

An OpenEnv benchmark where an agent audits Solidity contracts and reports vulnerabilities with type, location, severity, and fix suggestions.

## Environment Summary

| Property | Value |
|---|---|
| Environment Name | `smart_contract_auditor` |
| Runtime | Docker |
| App Entry | `server/app.py` |
| Default Port | `7860` |
| Tasks | `basic_audit`, `intermediate_audit`, `advanced_audit` |
| Model Access | OpenAI-compatible client over Hugging Face router |

## What This Environment Does

The environment provides Solidity contract code and accepts one finding per action. The agent can continue submitting findings or send `done` to finish the audit episode.

## Action Space

Actions are represented by `AuditAction`.

| Field | Type | Description |
|---|---|---|
| `vulnerability_type` | `str` | Vulnerability label or `done` |
| `location` | `str` | Function name where issue exists |
| `severity` | `str` | `critical` / `high` / `medium` / `low` |
| `fix_suggestion` | `str` | Remediation text |

Supported vulnerability labels:

`reentrancy`, `integer_overflow`, `access_control`, `unchecked_return`, `tx_origin`, `selfdestruct`, `timestamp_dependence`, `front_running`, `delegatecall`, `denial_of_service`, `precision_loss`, `flash_loan`, `oracle_manipulation`, `uninitialized_storage`, `done`

## Observation Space

Observations are represented by `AuditObservation`.

| Field | Type | Description |
|---|---|---|
| `done` | `bool` | Whether episode ended |
| `reward` | `float | null` | Step reward or final reward |
| `contract_code` | `str` | Solidity code under review |
| `contract_name` | `str` | Current contract name |
| `task_name` | `str` | Active task id |
| `findings_so_far` | `list[dict]` | Submitted findings |
| `remaining_steps` | `int` | Step budget left |
| `total_vulnerabilities_hint` | `int` | Hint count of vulnerabilities |
| `valid_vulnerability_types` | `list[str]` | Allowed labels (excluding `done`) |
| `message` | `str` | Feedback after each action |

## Tasks

### Easy - `basic_audit`
- Single vulnerability in a short contract.

### Medium - `intermediate_audit`
- Two vulnerabilities with mixed patterns.

### Hard - `advanced_audit`
- Three vulnerabilities with subtle bugs and red herrings.

## Reward Function

Per-finding scoring:
- type match: `+0.4`
- location match: `+0.3`
- severity match: `+0.1`
- quality fix suggestion: `+0.2`

Final episode score:
- normalized by number of target vulnerabilities
- false-positive penalty: `0.05` per unmatched finding
- clipped to `[0.0, 1.0]`

## API Endpoints (OpenEnv)

| Method | Path | Description |
|---|---|---|
| `POST` | `/reset` | Start a new episode |
| `POST` | `/step` | Submit one audit action |
| `GET` | `/state` | Read current environment state |
| `GET` | `/health` | Health check |
| `GET` | `/docs` | API docs |

## Quick Start

### 1) Install dependencies
```bash
pip install -r requirements.txt
```

### 2) Run from source
```bash
python -m server.app
```

Open in browser:
```text
http://127.0.0.1:7860
```

### 3) Run the baseline scripts
```bash
python inference.py
python inference_rl.py --task basic_audit --num-runs 5
```

## Expected Inference Log Format

`inference.py` prints these line types:

```text
[START] task=<task_name> env=smart_contract_auditor model=<model_name>
[STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
[END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `HF_TOKEN` | Yes | Hugging Face API token |
| `API_BASE_URL` | Yes | OpenAI-compatible API base URL |
| `MODEL_NAME` | Yes | LLM model id |
| `LOCAL_IMAGE_NAME` | No | Local Docker image tag |
| `GRADIO_SERVER_PORT` | No | Override local port |
| `PORT` | No | Hosted runtime port |

Example `.env`:

```env
HF_TOKEN=hf_your_token_here
API_BASE_URL=https://router.huggingface.co/v1
MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
LOCAL_IMAGE_NAME=smart-contract-auditor
# Optional
# GRADIO_SERVER_PORT=7860
```

## Docker and Validation

```bash
openenv validate
docker build -t smart-contract-auditor .
docker run -d --name smart-contract-auditor-test -p 7860:7860 smart-contract-auditor
curl http://127.0.0.1:7860/health
```

## Key Project Files

```text
.
├── environment.py
├── models.py
├── contracts.py
├── inference.py
├── inference_rl.py
├── dashboard.py
├── server/
│   └── app.py
├── openenv.yaml
└── README.md
```

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| `Errno 10048` on startup | Port `7860` already used | Kill process on `7860`, restart app |
| Browser shows `0.0.0.0` error | Wrong URL in browser | Use `http://127.0.0.1:7860` |
| LLM auth fails | Missing/invalid token | Set correct `HF_TOKEN` |
| LLM request mismatch | Wrong endpoint/model | Check `API_BASE_URL` and `MODEL_NAME` |

## License

MIT
