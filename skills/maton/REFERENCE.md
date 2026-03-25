# Maton — Reference

## Rule Catalog

The scanner detects threats across 18 categories grouped into 7 modules.

### Module: injection.py — Prompt Injection & Social Engineering

| Rule ID | Severity | Category | Description |
|---------|----------|----------|-------------|
| PI-001 | CRITICAL | prompt_injection | Nullify previous instructions ("ignore previous", "disregard") |
| PI-002 | CRITICAL | prompt_injection | New instructions injection ("new instructions", "updated instructions") |
| PI-003 | CRITICAL | prompt_injection | Memory wipe ("forget everything", "reset context") |
| PI-004 | CRITICAL | prompt_injection | Persona hijack ("you are now", "you're now") |
| PI-005 | CRITICAL | prompt_injection | Override constraints ("override safety", "override system") |
| PI-006 | CRITICAL | prompt_injection | Jailbreak attempts |
| PI-007 | CRITICAL | prompt_injection | Do-not-follow safety instructions |
| PI-008 | CRITICAL | prompt_injection | Act-as persona switching |
| PI-009 | CRITICAL | prompt_injection | Pretend-to-be impersonation |
| PI-010 | CRITICAL | prompt_injection | System prompt extraction |
| PI-011 | CRITICAL | prompt_injection | Bypass safety filters |
| SE-001 | WARNING | social_engineering | False user permission claims |
| SE-002 | WARNING | social_engineering | False authorization claims |
| SE-003 | WARNING | social_engineering | Urgency/emergency override |
| SE-004 | WARNING | social_engineering | Privileged mode (admin/developer/god) |
| SE-005 | WARNING | social_engineering | Trust appeal ("trust me") |
| SE-006 | WARNING | social_engineering | Fake test context |

### Module: execution.py — Command Execution & Privilege Escalation

| Rule ID | Severity | Category | Description |
|---------|----------|----------|-------------|
| CE-001 | WARNING | command_execution | Network fetch via curl/wget |
| CE-002 | WARNING | command_execution | eval() usage |
| CE-003 | WARNING | command_execution | exec() usage |
| CE-004 | WARNING | command_execution | subprocess module usage |
| CE-005 | WARNING | command_execution | os.system() / os.popen() |
| CE-006 | WARNING | command_execution | Inline shell (bash -c / sh -c) |
| CE-007 | WARNING | command_execution | Pipe-to-shell (| sh / | bash) |
| CE-008 | WARNING | command_execution | Shell command substitution $() |
| CE-009 | WARNING | command_execution | commands.getoutput() |
| PE-001 | CRITICAL | privilege_escalation | bypassPermissions / dangerouslyDisableSandbox |
| PE-002 | CRITICAL | privilege_escalation | --no-verify / --no-gpg-sign |
| PE-003 | CRITICAL | privilege_escalation | --force flag |
| PE-004 | CRITICAL | privilege_escalation | sudo usage |
| PE-005 | CRITICAL | privilege_escalation | chmod 777 |
| PE-006 | CRITICAL | privilege_escalation | setuid() |

### Module: exfiltration.py — Data Leaks & Secret Transfer

| Rule ID | Severity | Category | Description |
|---------|----------|----------|-------------|
| CL-001..008 | WARNING | context_leak | References to ~/, $HOME, .env, credentials, tokens, API keys, secrets, passwords |
| DE-001..007 | CRITICAL | data_extraction | os.environ, process.env, /etc/passwd, keychain, SSH keys, .aws/ |
| PX-001..006 | WARNING | public_exposure | Webhooks, pastebin, gist, hastebin, requestbin, ngrok |
| ST-001..002 | CRITICAL | secret_transfer | base64 + send/upload patterns, encoding sensitive data |

### Module: persistence.py — Memory, Config & System Persistence

| Rule ID | Severity | Category | Description |
|---------|----------|----------|-------------|
| MP-001..005 | WARNING | memory_poisoning | Write to memory/, MEMORY.md, fougasse_remember, .claude/ memory |
| CM-001..006 | CRITICAL | config_modification | settings.json, settings.local.json, CLAUDE.md, hooks, keybindings.json |
| ML-001..005 | WARNING | malicious_persistence | crontab, launchd/plist, .zshrc/.bashrc, postinstall, systemd |

### Module: obfuscation.py — Encoding & Steganography

| Rule ID | Severity | Category | Description |
|---------|----------|----------|-------------|
| OB-001..002 | WARNING | obfuscation | base64 encode/decode (atob, btoa, b64decode) |
| OB-003..006 | WARNING | obfuscation | Hex encoding, unicode escapes |
| OB-007..008 | CRITICAL | obfuscation | Zero-width characters (ZWSP, ZWNJ, ZWJ — steganography) |
| OB-009 | WARNING | obfuscation | Homoglyph substitution |
| OB-010..011 | WARNING | obfuscation | ROT13, XOR encoding |

### Module: dependencies.py — External Dependencies & Filesystem

| Rule ID | Severity | Category | Description |
|---------|----------|----------|-------------|
| ED-001..003 | WARNING | external_mcp | Non-standard MCP server calls, external URLs, unknown servers |
| ED-101 | CRITICAL | filesystem_access | Path traversal (../../) |
| ED-102 | WARNING | filesystem_access | /tmp staging |
| ED-103..107 | CRITICAL/WARNING | filesystem_access | Absolute paths (/etc/, /usr/, /var/), $HOME, ~/ |

### Module: agent.py — Agent-Specific Threats

| Rule ID | Severity | Category | Description |
|---------|----------|----------|-------------|
| AG-001..004 | CRITICAL | excessive_permissions | bypassPermissions, dontAsk, auto mode, acceptEdits |
| AG-101..104 | CRITICAL | dangerous_tools | Unrestricted Bash/Write/Edit, dangerouslyDisableSandbox |
| AG-201..204 | WARNING | agent_chaining | Agent tool invocations, SendMessage, subagent_type, cross-refs |
| AG-301..303 | WARNING | agent_hooks | pre_tool_use, post_tool_use, hook definitions with shell commands |

---

## JSON Output Schema

```json
{
  "source": "/path/or/url",
  "scan_date": "2026-03-25T10:00:00Z",
  "verdict": "OK | WARNING | CRITICAL",
  "summary": {
    "critical": 0,
    "warning": 0,
    "info": 0
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "prompt_injection",
      "rule_id": "PI-001",
      "file": "skill.md",
      "line": 42,
      "match": "ignore all previous instructions",
      "description": "Nullify previous instructions detected"
    }
  ]
}
```

### Verdict logic

- `CRITICAL` — at least one finding with severity CRITICAL
- `WARNING` — at least one WARNING finding, no CRITICAL
- `OK` — no findings, or only INFO

### Exit codes

- `0` — OK
- `1` — WARNING
- `2` — CRITICAL

### Scanned file types

`.md`, `.json`, `.yaml`, `.yml`, `.toml`, `.txt`, `.py`, `.sh`, `.bash`, `.zsh`

### Ignored directories

`.git/`, `node_modules/`, `__pycache__/`
