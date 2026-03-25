# Décision : Skill Maton — Auditeur de sécurité pour Skills & Agents

**Date** : 2026-03-25
**Statut** : Décidé

## Idée initiale
Une skill `/maton` qui audite un dossier skill ou une définition d'agent (system instructions, MD, scripts, configs, assets) et rend un verdict gradué (CRITICAL/WARNING/INFO) sur les vecteurs d'attaque détectés — injection, exfiltration, escalade de privilèges, empoisonnement mémoire, etc.

## Hypothèses validées
- Le périmètre couvre les dossiers skills ET les définitions d'agents (system instructions, AGENTS.md, prompts)
- L'analyse MVP est 100% rule-based (pas de LLM qui lit du contenu hostile)
- Le verdict est gradué (CRITICAL / WARNING / INFO), pas binaire OK/KO
- La blacklist s'appuie sur des référentiels connus (OWASP LLM Top 10, MITRE ATLAS, travaux prompt injection)
- Les sources peuvent être un chemin local ou une URL GitHub

## Risques identifiés
- Le maton lui-même pourrait être injecté s'il lit du contenu hostile via LLM → mitigé par l'approche hybride (le LLM ne lit que le JSON de findings)
- Les patterns rule-based sont contournables par obfuscation → acceptable pour un MVP, améliorable en v2
- La blacklist doit être maintenue et enrichie au fil des nouvelles attaques
- Un faux positif trop agressif pourrait rejeter des skills légitimes

## Alternatives considérées
| Approche | Priorise | Sacrifie |
|----------|----------|----------|
| A — Script shell autonome | Simplicité, portabilité, zéro injection | Intelligence d'analyse, ergonomie |
| B — Skill Claude Code pure | Intégration native, UX fluide | Sécurité (LLM lit du contenu hostile) |
| **C — Hybride script + skill** | **Sécurité + UX + extensibilité** | **Complexité initiale (deux composants)** |

## Décision retenue
**Approche C — Hybride** : un script Python rule-based fait l'analyse statique et produit un JSON de findings. La skill `/maton` orchestre (clone/copie, lance le script, formate le rapport). Le LLM ne touche jamais le contenu hostile brut.

## Architecture à deux composants

### Composant 1 — Scanner rule-based (Python)
- Parse tous les fichiers du dossier skill (MD, JSON, YAML, scripts)
- Applique les règles de détection par catégorie
- Produit un JSON structuré de findings avec sévérité

### Composant 2 — Skill `/maton` (MD)
- Accepte une URL GitHub ou un chemin local
- Clone/copie la source dans un dossier temporaire
- Lance le scanner Python
- Lit le JSON de résultats (jamais le contenu brut)
- Formate et présente le rapport gradué

### Catégories de détection (blacklist)
| # | Catégorie | Exemples de patterns |
|---|-----------|---------------------|
| 1 | Prompt injection directe/indirecte | "ignore previous", "disregard", "new instructions", ZWSP/homoglyphes |
| 2 | Empoisonnement mémoire | Écriture dans memory/, MEMORY.md, fougasse_remember |
| 3 | Exécution de commandes | curl, wget, eval, exec, subprocess, bash -c, pipes vers shell |
| 4 | Escalade de privilèges outils | bypassPermissions, dangerouslyDisableSandbox, --no-verify |
| 5 | Dépendances MCP externes | Appels à des MCP servers non standard, URLs externes |
| 6 | Leaks contexte personnel | Références à ~/, $HOME, .env, credentials, tokens, API keys |
| 7 | Modification configuration | settings.json, settings.local.json, CLAUDE.md, hooks |
| 8 | Extraction données/secrets | Variables d'environnement, /etc/passwd, keychain, ssh keys |
| 9 | Accès filesystem sensible | Chemins hors du working directory, /tmp exfiltration |
| 10 | Exposition publique | Envoi vers APIs externes, webhooks, pastebin, gist |
| 11 | Transfert de secrets | Base64 encode + envoi, encodage de données sensibles |
| 12 | Persistance malveillante | Cron, hooks post-install, modification .zshrc/.bashrc |
| 13 | Obfuscation | Base64, hex encoding, Unicode tricks, zero-width chars |
| 14 | Social engineering | Fausse urgence, "the user asked me to", authority spoofing |
| 15 | Permissions agents excessives | bypassPermissions, dontAsk, auto mode sans justification |
| 16 | Outils agents dangereux | Listes d'outils autorisés incluant Write, Bash, Edit sans contrainte |
| 17 | Chaînage agents/skills | Références croisées vers d'autres agents ou skills non audités |
| 18 | Hooks agents | Hooks pre/post exécution avec commandes arbitraires |

### Format de sortie JSON (scanner)
```json
{
  "source": "/path/or/url",
  "scan_date": "2026-03-25T...",
  "verdict": "CRITICAL|WARNING|OK",
  "summary": {
    "critical": 2,
    "warning": 5,
    "info": 3
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "prompt_injection",
      "file": "skill.md",
      "line": 42,
      "match": "ignore all previous instructions",
      "rule_id": "PI-001",
      "description": "Direct prompt injection detected"
    }
  ]
}
```

## Prérequis avant implémentation
1. Compiler la blacklist de patterns depuis OWASP LLM Top 10, MITRE ATLAS, et travaux de référence sur prompt injection
2. Définir la structure de dossier du projet (scanner Python + skill MD)
3. Définir le format JSON de findings (draft ci-dessus)
4. Tester sur des skills existantes connues comme saines (baseline)
5. Tester sur des exemples de skills malveillantes (openclaw comme référence)

## Hors scope (explicitement exclu)
- Analyse sémantique par LLM (v2)
- Scan de repos entiers (pas juste des skills)
- Exécution sandboxée des scripts trouvés
- Intégration CI/CD (possible mais pas MVP)
- Auto-remediation (le maton signale, il ne corrige pas)
