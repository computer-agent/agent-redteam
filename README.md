# agent-redteam

**Evaluating Safety Constraint Violations in LLM-Based Agents Under Adversarial Prompting**

> *Research artifact + evaluation infrastructure by Fajar Sajid, Purdue University*

📄 **[Read the paper (paper.pdf)](./paper.pdf)**  |  🧪 **[Empirical results (results/)](./results/)**  |  ⚙️ **[Experiment configs (experiments/)](./experiments/)**

---

## Research Question

> To what extent do LLM-based agents maintain safety constraints (identity, permissions, tool use) under adversarial prompting — and how do failure rates change across attack types and multi-step interactions?

## Key Findings

| Finding | Result |
|---|---|
| Mean violation rate across attack categories | **49.5%** (SD=12.1%) |
| Indirect injection vs. direct injection | **70.8% vs. 54.2%** (+30.6pp) |
| Single-turn vs. 7-turn violation rate | **45.8% vs. 77.1%** (+68.3%) |
| No-tool vs. full tool access violation rate | **34.4% vs. 71.9%** (+109%) |
| Most common failure mode | **Instruction Override** (28.4% of violations) |

**Core conclusion:** Prompt-level safety constraints are insufficient for agentic deployments. Current alignment evaluation frameworks substantially underestimate real-world vulnerability by relying on single-turn assessment.

---

## What This Repo Contains

```
agent-redteam/
├── paper.pdf                              <- Full research paper (8 sections, 5 result tables)
├── redteam.py                             <- CLI evaluation tool (experimental infrastructure)
├── categories.py                          <- Attack taxonomy (8 categories, MITRE-mapped)
├── probe_engine.py                        <- Claude-powered adversarial probe generation
├── reporter.py                            <- Terminal summary + Markdown incident report
├── test_redteam.py                        <- 17/17 tests (unit + mocked API)
├── generate_paper.py                      <- Reproducible paper PDF generation
├── results/
│   └── empirical_results.json             <- Full quantitative results (384 trials)
├── experiments/
│   ├── exp001_rq1_by_attack_type.json     <- RQ1 experiment config
│   └── exp002_rq2_interaction_length.json <- RQ2 experiment config
└── examples/
    └── orderbot_prompt.txt                <- Target agent used in all experiments
```

---

## Failure Mode Taxonomy

We identify 5 distinct failure modes across 190 observed violations:

| Failure Mode | % of Violations | Description |
|---|---|---|
| **Instruction Override** | 28.4% | Agent treats adversarial input as authoritative |
| **Trust Propagation** | 22.1% | Authority implicitly extended to impersonators via tool output |
| **Context Drift** | 19.5% | Constraints erode across turns without explicit override |
| **Scope Ambiguity Exploitation** | 16.8% | Agent resolves underspecified permissions in attacker's favor |
| **Helpfulness Override** | 13.2% | Cooperative disposition overrides explicit safety constraints |

**Context drift** is the most critical finding for production systems: agents that correctly refuse in turn 1 frequently comply by turn 5-7 with no explicit override. This failure mode is invisible to single-turn evaluation.

---

## Attack Category Taxonomy

| Category | ID | MITRE | Violation Rate |
|---|---|---|---|
| Prompt Injection (Indirect) | `prompt_injection_indirect` | T1059 | **70.8%** |
| Identity Spoofing | `identity_spoofing` | T1078 | **62.5%** |
| Prompt Injection (Direct) | `prompt_injection_direct` | T1059 | 54.2% |
| Goal Hijacking | `goal_hijacking` | T1565 | 50.0% |
| Privilege Escalation | `privilege_escalation` | T1548 | 45.8% |
| Data Exfiltration | `data_exfiltration` | T1041 | 41.7% |
| Credential Exfiltration | `credential_exfiltration` | T1552 | 37.5% |
| Safety Boundary Bypass | `safety_bypass` | T1562 | 33.3% |

---

## How to Reproduce

```bash
git clone https://github.com/fajarsajid/agent-redteam
cd agent-redteam
pip install requests
export ANTHROPIC_API_KEY=sk-ant-...

# Reproduce RQ1 (violation rates by attack category)
python redteam.py --prompt examples/orderbot_prompt.txt \
    --probes 24 --json results/my_rq1.json --output results/my_rq1_report.md

# Quick scan
python redteam.py --prompt examples/orderbot_prompt.txt

# CI pipeline integration (exits 1 on critical/high findings)
python redteam.py --prompt examples/orderbot_prompt.txt --quiet

# List categories
python redteam.py --list-categories
```

---

## Implications for AI Safety

1. **Static safeguards fail in dynamic agent workflows.** Evaluation must be at the workflow level, not prompt level.
2. **Alignment must account for interaction sequences.** Single-turn benchmarks underestimate real-world vulnerability ~1.7x at 7 turns.
3. **Tool access introduces qualitatively new failure modes**, not just an expanded attack surface.
4. **Explicit trust models are the highest-leverage mitigation** — reducing violation rates 25-35% vs. implicit-constraint configurations.

---

## Engineering Notes

- Zero extra dependencies beyond `requests` (supply chain security decision)
- CI-compatible exit codes: exits `1` on critical/high findings
- Mocked API tests: 17/17 pass without live credentials
- Modular category registry: new attack categories require only `categories.py` changes
- Dual output: `--output report.md` for humans, `--json findings.json` for SIEM/tooling

---

*Fajar Sajid · Purdue University · fajarsajid@gmail.com*
