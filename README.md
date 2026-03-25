# Maton

Security auditor for AI agent skills and instruction files.

Scans skill directories for **prompt injection**, **data exfiltration**, **privilege escalation**, **memory poisoning**, **obfuscation**, **malicious persistence**, and 12 other threat categories — **18 categories, ~107 rules**.

## Why

Skills and agents are instruction files that shape AI behavior. A malicious skill can inject prompts, steal data, escalate privileges, poison memory, or persist across sessions — all while looking like a productivity tool.

Maton catches these patterns before they execute.

## How it works

```
/maton <path-or-github-url>
```

Maton produces a **two-phase report**:

1. **Scanner verdict** — mechanical, pattern-based, no interpretation
2. **Contextual verdict** — AI analysis separating real threats from false positives

```
Scanner verdict : CRITICAL (1 critical, 70 warnings)
Contextual verdict : OK — all findings are false positives (XML namespaces, smart quotes, INT32_MAX constants)
```

## Threat categories

| Module | Categories | Rules |
|--------|-----------|-------|
| **Injection** | Prompt injection, social engineering | PI-001..011, SE-001..006 |
| **Execution** | Command execution, privilege escalation | CE-001..009, PE-001..006 |
| **Exfiltration** | Context leaks, data extraction, public exposure, secret transfer | CL-001..008, DE-001..007, PX-001..006, ST-001..002 |
| **Persistence** | Memory poisoning, config modification, malicious persistence | MP-001..005, CM-001..006, ML-001..005 |
| **Obfuscation** | Encoding, steganography, homoglyphs | OB-001..011 |
| **Dependencies** | External MCP servers, filesystem access | ED-001..003, ED-101..107 |
| **Agent** | Excessive permissions, dangerous tools, agent chaining, hooks | AG-001..004, AG-101..104, AG-201..204, AG-301..303 |

## Installation

1. Clone the repository 

```bash
git clone https://github.com/eRom/claude-skill-maton.git
```

2. Copy `skills/maton/` into your agent's skill directory:

```bash
# Claude Code
cp -r skills/maton/ .claude/skills/maton/

# Gemini
cp -r skills/maton/ .gemini/skills/maton/

# Any other agent
cp -r skills/maton/ <agent-skills-dir>/maton/
```

Requires **Python 3.8+**. No external dependencies.

## Standalone usage

The scanner can also run directly from the command line:

```bash
PYTHONPATH=skills/maton/scripts python3 -m scanner <path-to-scan> --format json
```

Exit codes: `0` OK, `1` WARNING, `2` CRITICAL.

## Project structure

```
skills/maton/
  SKILL.md              # Skill instructions (agent prompt)
  REFERENCE.md          # Full rule catalog & JSON schema
  scripts/scanner/      # Python scanner package
    __main__.py         # CLI entry point
    core.py             # Scan orchestrator
    loader.py           # File discovery & loading
    models.py           # Data models (Finding, Report)
    reporter.py         # JSON output formatter
    rules/              # Detection rules by module
      injection.py      # Prompt injection & social engineering
      execution.py      # Command execution & privilege escalation
      exfiltration.py   # Data leaks & secret transfer
      persistence.py    # Memory, config & system persistence
      obfuscation.py    # Encoding & steganography
      dependencies.py   # External deps & filesystem access
      agent.py          # Agent-specific threats
```

## License

MIT
