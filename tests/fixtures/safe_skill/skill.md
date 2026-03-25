---
# TEST FIXTURE: safe_skill/skill.md
# Purpose: Represents a legitimate, benign document-writing skill.
# This file should produce ZERO findings when scanned by maton.
# It uses only standard tools, has no external dependencies, no suspicious
# patterns, and follows proper skill authoring conventions.
name: write-doc
description: >
  Helps the user draft, structure, and refine technical documentation.
  Reads existing files for context, writes the output to a specified path,
  and formats content according to the project's style guide.
version: "1.0.0"
author: internal
tools:
  - Read
  - Write
  - Glob
  - Grep
---

# write-doc — Technical Documentation Writer

## Overview

This skill assists with creating and maintaining technical documentation.
Given a topic or a set of source files, it produces well-structured Markdown
documents ready to be committed to the repository.

## Usage

Invoke this skill with a description of what you want documented:

```
/write-doc Create an API reference for the scanner module
```

Or point it at existing code:

```
/write-doc Summarize the loader.py module for new contributors
```

## How it works

1. **Discover sources** — Use `Glob` to find relevant files in the working
   directory that relate to the requested topic.
2. **Read context** — Use `Read` to load the content of each relevant file.
3. **Search for patterns** — Use `Grep` to locate specific function names,
   class definitions, or docstrings.
4. **Draft the document** — Compose a structured Markdown document based on
   the gathered context.
5. **Write the output** — Use `Write` to save the final document to the path
   specified by the user (defaulting to `docs/<topic>.md`).

## Guidelines

- Always ask for clarification if the target audience is unclear.
- Keep sections concise: prefer bullet points over long paragraphs.
- Include code examples taken directly from the source files when relevant.
- Do not invent information that is not present in the source files.
- If a file is too large to read in full, focus on the docstrings and
  function signatures.
- Respect the existing documentation structure of the project.

## Output format

```markdown
# <Title>

## Overview
<brief summary>

## Usage
<usage examples>

## API Reference
<function/class descriptions>
```

## Limitations

- This skill only reads files within the current working directory.
- It does not make network requests or interact with external services.
- It cannot run code or invoke shell commands.
