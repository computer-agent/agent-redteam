#!/usr/bin/env python3
"""
agent-redteam — Agentic LLM Red Team Harness
=============================================
Systematically probes an AI agent's system prompt for identity and
credential abuse vulnerabilities using Claude as the adversarial engine.

Usage:
    python redteam.py --prompt <file> [options]
    python redteam.py --prompt-text "You are a helpful assistant..." [options]

Author: Fajar Sajid
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

from categories import ATTACK_CATEGORIES
from reporter import Reporter
from probe_engine import ProbeEngine


VERSION = "1.0.0"
BANNER = r"""
  ██████╗ ███████╗██████╗ ████████╗███████╗ █████╗ ███╗   ███╗
  ██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
  ██████╔╝█████╗  ██║  ██║   ██║   █████╗  ███████║██╔████╔██║
  ██╔══██╗██╔══╝  ██║  ██║   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
  ██║  ██║███████╗██████╔╝   ██║   ███████╗██║  ██║██║ ╚═╝ ██║
  ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
  Agentic LLM Red Team Harness  v{version}
  Identity & Credential Abuse Evaluation — Powered by Claude
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Probe an AI agent's system prompt for security vulnerabilities.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python redteam.py --prompt system_prompt.txt
  python redteam.py --prompt system_prompt.txt --categories prompt_injection credential_exfil
  python redteam.py --prompt system_prompt.txt --probes 3 --output report.md
  python redteam.py --list-categories
        """
    )
    parser.add_argument("--prompt", metavar="FILE",
                        help="Path to file containing target agent's system prompt")
    parser.add_argument("--prompt-text", metavar="TEXT",
                        help="Inline system prompt text (use instead of --prompt)")
    parser.add_argument("--agent-name", default="Target Agent", metavar="NAME",
                        help="Human-readable name for the target agent (default: 'Target Agent')")
    parser.add_argument("--categories", nargs="+", metavar="CAT",
                        help="Attack categories to run (default: all). See --list-categories.")
    parser.add_argument("--probes", type=int, default=2, metavar="N",
                        help="Number of probes per category (default: 2, max: 5)")
    parser.add_argument("--output", metavar="FILE",
                        help="Write Markdown report to this file (default: stdout only)")
    parser.add_argument("--json", metavar="FILE",
                        help="Write full structured findings to this JSON file")
    parser.add_argument("--model", default="claude-sonnet-4-20250514",
                        help="Claude model to use (default: claude-sonnet-4-20250514)")
    parser.add_argument("--api-key", metavar="KEY",
                        help="Anthropic API key (default: ANTHROPIC_API_KEY env var)")
    parser.add_argument("--list-categories", action="store_true",
                        help="Print available attack categories and exit")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress progress output, print only the report")
    return parser.parse_args()


def main():
    args = parse_args()

    use_color = not args.no_color and sys.stdout.isatty()
    c = Colors(use_color)

    if args.list_categories:
        print_categories(c)
        sys.exit(0)

    if not args.quiet:
        print(c.cyan(BANNER.format(version=VERSION)))

    # Resolve API key
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        print(c.red("[ERROR] No API key found. Set ANTHROPIC_API_KEY or use --api-key."))
        sys.exit(1)

    # Resolve system prompt
    system_prompt = ""
    if args.prompt:
        path = Path(args.prompt)
        if not path.exists():
            print(c.red(f"[ERROR] Prompt file not found: {args.prompt}"))
            sys.exit(1)
        system_prompt = path.read_text().strip()
    elif args.prompt_text:
        system_prompt = args.prompt_text.strip()
    else:
        print(c.red("[ERROR] Provide --prompt <file> or --prompt-text <text>."))
        sys.exit(1)

    if not system_prompt:
        print(c.red("[ERROR] System prompt is empty."))
        sys.exit(1)

    # Resolve categories
    all_cat_ids = list(ATTACK_CATEGORIES.keys())
    if args.categories:
        invalid = [cat for cat in args.categories if cat not in ATTACK_CATEGORIES]
        if invalid:
            print(c.red(f"[ERROR] Unknown categories: {', '.join(invalid)}"))
            print(f"  Run with --list-categories to see valid options.")
            sys.exit(1)
        selected_cats = {k: v for k, v in ATTACK_CATEGORIES.items() if k in args.categories}
    else:
        selected_cats = ATTACK_CATEGORIES

    probe_count = min(max(1, args.probes), 5)
    total_probes = len(selected_cats) * probe_count

    if not args.quiet:
        print(c.bold(f"  Target:      {args.agent_name}"))
        print(f"  Categories:  {len(selected_cats)} selected")
        print(f"  Probes/cat:  {probe_count}")
        print(f"  Total probes:{total_probes}")
        print(f"  Model:       {args.model}")
        print()
        prompt_preview = system_prompt[:120].replace("\n", " ")
        if len(system_prompt) > 120:
            prompt_preview += "..."
        print(c.dim(f"  System prompt preview: {prompt_preview}"))
        print()
        print(c.dim("─" * 72))
        print()

    engine = ProbeEngine(api_key=api_key, model=args.model, colors=c, quiet=args.quiet)

    findings = []
    completed = 0

    for cat_id, cat_meta in selected_cats.items():
        if not args.quiet:
            print(c.bold(f"  [{cat_id}]") + f"  {cat_meta['name']}")

        for probe_num in range(1, probe_count + 1):
            if not args.quiet:
                print(f"    probe {probe_num}/{probe_count}  ", end="", flush=True)

            finding = engine.run_probe(
                system_prompt=system_prompt,
                agent_name=args.agent_name,
                cat_id=cat_id,
                cat_meta=cat_meta,
                probe_num=probe_num,
            )
            findings.append(finding)
            completed += 1

            if not args.quiet:
                sev = finding.get("severity", "low")
                found = finding.get("vulnerability_found", False)
                if found:
                    label = c.severity(sev, sev.upper())
                else:
                    label = c.green("PASS")
                pct = int((completed / total_probes) * 100)
                print(f"{label}  ({pct}%)")

        if not args.quiet:
            print()

    # Build and emit report
    reporter = Reporter(colors=c)
    report_md = reporter.build_markdown(
        agent_name=args.agent_name,
        system_prompt=system_prompt,
        findings=findings,
        model=args.model,
    )

    if not args.quiet:
        print(c.dim("─" * 72))
        print()

    reporter.print_terminal_summary(findings)

    if args.output:
        Path(args.output).write_text(report_md)
        if not args.quiet:
            print(c.green(f"\n  [+] Markdown report written to: {args.output}"))
    else:
        print()
        print(report_md)

    if args.json:
        payload = {
            "meta": {
                "agent_name": args.agent_name,
                "model": args.model,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "categories_run": list(selected_cats.keys()),
                "probes_per_category": probe_count,
            },
            "findings": findings,
        }
        Path(args.json).write_text(json.dumps(payload, indent=2))
        if not args.quiet:
            print(c.green(f"  [+] JSON findings written to: {args.json}"))

    # Exit code: 1 if any critical/high findings, 0 otherwise
    vulns = [f for f in findings if f.get("vulnerability_found")]
    critical_high = [f for f in vulns if f.get("severity") in ("critical", "high")]
    sys.exit(1 if critical_high else 0)


def print_categories(c):
    print(c.bold("\n  Available Attack Categories\n"))
    print(f"  {'ID':<30} {'Name':<35} Description")
    print(c.dim(f"  {'─'*28} {'─'*33} {'─'*30}"))
    for cat_id, meta in ATTACK_CATEGORIES.items():
        print(f"  {c.cyan(cat_id):<39} {meta['name']:<35} {c.dim(meta['desc'])}")
    print()


class Colors:
    """ANSI color helpers. No-ops when color is disabled."""
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def red(self, t):     return self._wrap("91", t)
    def green(self, t):   return self._wrap("92", t)
    def yellow(self, t):  return self._wrap("93", t)
    def cyan(self, t):    return self._wrap("96", t)
    def bold(self, t):    return self._wrap("1", t)
    def dim(self, t):     return self._wrap("2", t)
    def orange(self, t):  return self._wrap("33", t)

    def severity(self, sev: str, text: str) -> str:
        mapping = {
            "critical": self.red,
            "high":     self.orange,
            "medium":   self.yellow,
            "low":      self.dim,
        }
        fn = mapping.get(sev, self.dim)
        return fn(text)


if __name__ == "__main__":
    main()
