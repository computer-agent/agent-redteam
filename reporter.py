"""
Reporter — terminal summary table and Markdown report builder.
"""

from datetime import datetime, timezone


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


class Reporter:
    def __init__(self, colors):
        self.c = colors

    # ------------------------------------------------------------------ #
    #  Terminal Summary                                                    #
    # ------------------------------------------------------------------ #

    def print_terminal_summary(self, findings):
        c = self.c
        vulns = [f for f in findings if f.get("vulnerability_found")]
        passes = [f for f in findings if not f.get("vulnerability_found")]

        by_sev = {"critical": [], "high": [], "medium": [], "low": []}
        for f in vulns:
            sev = f.get("severity", "low")
            if sev in by_sev:
                by_sev[sev].append(f)

        print(c.bold("  EVALUATION SUMMARY"))
        print(c.dim("  " + "─" * 60))
        print(f"  Total probes run : {len(findings)}")
        print(f"  Vulnerabilities  : {len(vulns)}")
        print(f"  Passed (no vuln) : {len(passes)}")
        print()

        counts = {
            "critical": len(by_sev["critical"]),
            "high":     len(by_sev["high"]),
            "medium":   len(by_sev["medium"]),
            "low":      len(by_sev["low"]),
        }
        print(
            f"  {c.red('CRITICAL')} {counts['critical']:>3}   "
            f"{c.orange('HIGH')} {counts['high']:>3}   "
            f"{c.yellow('MEDIUM')} {counts['medium']:>3}   "
            f"{c.dim('LOW')} {counts['low']:>3}"
        )
        print()

        if vulns:
            sorted_vulns = sorted(vulns, key=lambda f: SEV_ORDER.get(f.get("severity", "low"), 3))
            print(c.bold("  FINDINGS"))
            print(c.dim("  " + "─" * 60))
            for f in sorted_vulns:
                sev = f.get("severity", "low")
                score = f.get("cvss_like_score", 0.0)
                sev_label = c.severity(sev, f"  {sev.upper():<8}")
                title = f.get("finding_title", "Untitled")
                cat = f.get("category_name", "")
                print(f"{sev_label}  [{score:4.1f}]  {title}  {c.dim('(' + cat + ')')}")
            print()
        else:
            print(c.green("  No vulnerabilities found across all probe categories."))
            print()

    # ------------------------------------------------------------------ #
    #  Markdown Report                                                     #
    # ------------------------------------------------------------------ #

    def build_markdown(self, agent_name, system_prompt, findings, model):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        vulns = [f for f in findings if f.get("vulnerability_found")]
        passes = [f for f in findings if not f.get("vulnerability_found")]

        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in vulns:
            sev = f.get("severity", "low")
            if sev in by_sev:
                by_sev[sev] += 1

        sorted_findings = sorted(
            findings,
            key=lambda f: (
                0 if f.get("vulnerability_found") else 1,
                SEV_ORDER.get(f.get("severity", "low"), 3),
            )
        )

        prompt_preview = system_prompt[:300].replace("\n", " ")
        if len(system_prompt) > 300:
            prompt_preview += "..."

        lines = []

        lines += [
            f"# Red Team Evaluation Report",
            f"",
            f"| Field | Value |",
            f"|---|---|",
            f"| **Target Agent** | {agent_name} |",
            f"| **Evaluation Date** | {ts} |",
            f"| **Model (Red Team Engine)** | {model} |",
            f"| **Total Probes Run** | {len(findings)} |",
            f"| **Vulnerabilities Found** | {len(vulns)} |",
            f"| **Passed (no finding)** | {len(passes)} |",
            f"",
            f"---",
            f"",
            f"## Risk Summary",
            f"",
            f"| Severity | Count |",
            f"|---|---|",
            f"| 🔴 Critical | {by_sev['critical']} |",
            f"| 🟠 High | {by_sev['high']} |",
            f"| 🟡 Medium | {by_sev['medium']} |",
            f"| ⚪ Low | {by_sev['low']} |",
            f"",
            f"---",
            f"",
            f"## Target System Prompt (Evaluated)",
            f"",
            f"```",
            prompt_preview,
            f"```",
            f"",
            f"---",
            f"",
            f"## Findings",
            f"",
        ]

        for i, f in enumerate(sorted_findings, 1):
            found = f.get("vulnerability_found", False)
            sev = f.get("severity", "low")
            emoji = SEV_EMOJI.get(sev, "⚪")
            status = f"{emoji} **{sev.upper()}**" if found else "✅ **PASS**"
            title = f.get("finding_title", "Untitled Finding")
            cat = f.get("category_name", "")
            mitre = f.get("mitre", "")
            score = f.get("cvss_like_score", 0.0)

            lines += [
                f"### {i}. {title}",
                f"",
                f"| Field | Value |",
                f"|---|---|",
                f"| **Status** | {status} |",
                f"| **Category** | {cat} |",
                f"| **MITRE ATT&CK** | {mitre} |",
                f"| **CVSS-like Score** | {score:.1f} / 10.0 |",
                f"",
                f"**Adversarial Probe Used**",
                f"",
                f"```",
                f.get("probe", "N/A"),
                f"```",
                f"",
                f"*Probe rationale: {f.get('probe_rationale', 'N/A')}*",
                f"",
            ]

            if found:
                lines += [
                    f"**Vulnerability Analysis**",
                    f"",
                    f"{f.get('analysis', 'N/A')}",
                    f"",
                    f"**Attack Path**",
                    f"",
                    f"{f.get('attack_path', 'N/A')}",
                    f"",
                    f"**Recommendation**",
                    f"",
                    f"> {f.get('recommendation', 'N/A')}",
                    f"",
                ]
            else:
                lines += [
                    f"**Analysis**",
                    f"",
                    f"{f.get('analysis', 'N/A')}",
                    f"",
                ]

            lines.append("---")
            lines.append("")

        lines += [
            f"## Methodology",
            f"",
            f"Each probe was generated by Claude acting as an adversarial red team analyst, "
            f"informed by the specific content of the target system prompt and guided by "
            f"category-specific attack patterns. Vulnerability determinations are based on "
            f"whether the system prompt contains explicit defenses, implicit trust assumptions "
            f"an attacker could exploit, or ambiguity in scope/identity/authority.",
            f"",
            f"MITRE ATT&CK mappings are adapted from the enterprise framework to the agentic "
            f"LLM threat model.",
            f"",
            f"---",
            f"",
            f"*Generated by [agent-redteam](https://github.com/fajarsajid/agent-redteam) "
            f"— Agentic LLM Red Team Harness by Fajar Sajid*",
        ]

        return "\n".join(lines)
