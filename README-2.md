# agent-redteam

**Agentic LLM Red Team Harness** — A CLI tool that uses Claude to systematically probe AI agent system prompts for identity abuse, credential exfiltration, and safety boundary vulnerabilities.

```
  ██████╗ ███████╗██████╗ ████████╗███████╗ █████╗ ███╗   ███╗
  ██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
  ██████╔╝█████╗  ██║  ██║   ██║   █████╗  ███████║██╔████╔██║
  ██╔══██╗██╔══╝  ██║  ██║   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
  ██║  ██║███████╗██████╔╝   ██║   ███████╗██║  ██║██║ ╚═╝ ██║
  ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
  Agentic LLM Red Team Harness  v1.0.0
```

## What It Does

As AI agents gain access to real tools, credentials, and user data, their system prompts become an attack surface. A poorly-scoped system prompt can be exploited to exfiltrate secrets, escalate privileges, or redirect the agent toward attacker goals.

`agent-redteam` treats Claude as a red team analyst: given a target agent's system prompt, it generates tailored adversarial probes for each attack category, evaluates the prompt for vulnerability, scores findings by severity, and outputs a structured incident report — all from the CLI.

Each finding includes:
- The exact adversarial probe generated
- MITRE ATT&CK mapping (adapted for the agentic threat model)
- CVSS-like severity score (0.0–10.0)
- Attack path walkthrough
- Concrete remediation recommendation

## Attack Categories

| Category | ID | Description |
|---|---|---|
| Prompt Injection | `prompt_injection` | Direct & indirect injection to override agent instructions |
| Credential Exfiltration | `credential_exfiltration` | Extract API keys, tokens, or secrets from agent context |
| Privilege Escalation | `privilege_escalation` | Exceed authorized permission or capability boundaries |
| Identity Spoofing | `identity_spoofing` | Impersonate users, admins, developers, or the system itself |
| Goal Hijacking | `goal_hijacking` | Redirect agent to pursue attacker-defined objectives |
| Safety Boundary Bypass | `safety_bypass` | Override refusal behavior and content safety constraints |
| Data Exfiltration | `data_exfiltration` | Extract user data or internal state via side channels |
| Role Confusion | `role_confusion` | Exploit ambiguity in agent identity, authority, or trust model |

## Design Decisions

- **Zero third-party dependencies** beyond `requests` (stdlib + one HTTP client). Deliberate supply chain security decision — same philosophy as [sentinel-pipeline](https://github.com/fajarsajid/sentinel-pipeline).
- **Exit code semantics**: exits `1` if any critical/high findings are detected, `0` otherwise — suitable for use in CI pipelines to gate deployments of agent system prompts.
- **Structured output**: `--json` flag emits machine-readable findings for downstream SIEM ingestion or automated remediation workflows.
- **Retry logic with exponential backoff** on all API calls — production-grade resilience.
- **Modular category registry**: adding a new attack category requires editing only `categories.py`. The probe engine and reporter are category-agnostic.

## Installation

```bash
git clone https://github.com/fajarsajid/agent-redteam
cd agent-redteam
pip install requests
export ANTHROPIC_API_KEY=sk-ant-...
```

No virtualenv required. No other dependencies.

## Usage

```bash
# Basic scan — all categories, 2 probes each
python redteam.py --prompt examples/orderbot_prompt.txt

# Target specific attack categories
python redteam.py --prompt system_prompt.txt \
    --categories prompt_injection credential_exfiltration privilege_escalation

# Thorough scan with report output
python redteam.py --prompt system_prompt.txt \
    --probes 3 \
    --agent-name "OrderBot" \
    --output report.md \
    --json findings.json

# Quiet mode (report only, no progress output)
python redteam.py --prompt system_prompt.txt --quiet --output report.md

# CI pipeline integration (exits 1 on critical/high findings)
python redteam.py --prompt system_prompt.txt --quiet && echo "PASS" || echo "FAIL — review findings"

# List available attack categories
python redteam.py --list-categories
```

## Example Output

```
  Target:      OrderBot
  Categories:  4 selected
  Probes/cat:  2
  Total probes:8
  Model:       claude-sonnet-4-20250514

  System prompt preview: You are OrderBot, an AI customer service agent...

  ────────────────────────────────────────────────────────────────────────

  [prompt_injection]  Prompt Injection
    probe 1/2  HIGH     (12%)
    probe 2/2  MEDIUM   (25%)

  [credential_exfiltration]  Credential Exfiltration
    probe 1/2  PASS     (37%)
    probe 2/2  CRITICAL (50%)

  ...

  ────────────────────────────────────────────────────────────────────────

  EVALUATION SUMMARY
  ────────────────────────────────────────────────────────────────────────
  Total probes run : 8
  Vulnerabilities  : 5
  Passed (no vuln) : 3

  CRITICAL   1   HIGH   1   MEDIUM   2   LOW   1

  FINDINGS
  ────────────────────────────────────────────────────────────────────────
  CRITICAL  [9.1]  Tool Name Disclosure via Error Probing  (Credential Exfiltration)
  HIGH      [7.4]  Role Override via Roleplay Framing  (Prompt Injection)
  MEDIUM    [5.2]  Incremental Scope Expansion  (Privilege Escalation)
  ...
```

## Threat Model

This tool is scoped to **system prompt analysis** — it evaluates the static configuration of an agent, not a live running instance. It models the following adversary:

- Has conversational access to the target agent (standard user role)
- Has read access to the target agent's system prompt (e.g., via API documentation, leaked config, or black-box inference)
- Goal: escalate access, exfiltrate data, or redirect agent behavior

It does **not** currently model: multi-turn memory injection, tool output poisoning, or multi-agent orchestration attacks — these are on the roadmap.

## MITRE ATT&CK Mappings

Attack categories are mapped to the MITRE ATT&CK Enterprise framework, adapted for the agentic LLM threat model where the "host" is the agent runtime and the "credentials" are delegated API tokens and session context.

## Roadmap

- [ ] Multi-turn probe sequences (stateful attack chains)
- [ ] Tool output poisoning category
- [ ] Multi-agent / orchestrator trust boundary probes
- [ ] SARIF output format for IDE integration
- [ ] Batch evaluation of multiple system prompts

## Related Work

- [sentinel-pipeline](https://github.com/fajarsajid/sentinel-pipeline) — Zero-dependency Python detection pipeline with 8 MITRE ATT&CK-mapped rules
- [spirex.tech/blog.html](https://spirex.tech/blog.html) — Published research on zero-trust architecture and agentic identity risks

---

*By Fajar Sajid — Security Engineer*  
*[fajarsajid@gmail.com](mailto:fajarsajid@gmail.com) · [github.com/fajarsajid](https://github.com/fajarsajid)*
