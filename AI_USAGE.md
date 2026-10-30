# AI Usage Disclosure & Technical Validation Record

## 1. Which AI tools did you use?
- **Gemini (Google AI)** was utilized as an auxiliary coding assistant and technical reference partner during development.

## 2. How did AI assist you?
AI assisted with initial project scoping, boilerplate scaffolding for Python's `xml.etree.ElementTree` parsing structure, and drafting standard command-line parameter handling logic using `argparse`.

## 3. Which parts were generated or substantially suggested by AI?
- The fundamental syntax structure for traversing XML element trees (`root.findall('host')`, `host.findall('ports/port')`).
- Boilerplate boilerplate code setup for `argparse` argument definitions (`--input`, `--output`, `--format`).

## 4. What mistakes, insecure suggestions, or incorrect assumptions did AI make?
- **Static Risk Limitations:** Initial AI iterations relied exclusively on a rigid, hardcoded port dictionary. It completely missed unencrypted web services or management interfaces running on non-standard ports (e.g., HTTP running on port 8180), incorrectly classifying them as `Low/Info`.
- **Unhandled KeyErrors:** The AI-generated parser assumed that every `<service>` block in Nmap XML output contained valid `product` and `version` attributes, which caused runtime exceptions when encountering generic open ports lacking version banners.

## 5. How did you manually validate the generated code or output?
- Tested the execution script locally against a live Nmap scan output file generated against an intentionally vulnerable test lab (Metasploitable 2).
- Validated that all 23 open ports, service banners, and OS identification strings were extracted cleanly without skipped indices or missing records.
- Verified that output Markdown tables and JSON objects rendered correctly without syntax errors.

## 6. What did you change after reviewing the AI-generated work?
- **Developed Custom Dynamic Risk Engine (`evaluate_risk`):** Implemented programmatic keyword checking to inspect service names and banner strings dynamically (catching keywords like `bindshell`, `vnc`, `exec`, and unencrypted `http` protocols on alternative ports).
- **Added Defensive Error Handling:** Implemented null-checks (`if element is not None`) and fallback assignment strings (`"No banner"`, `"Not Scanned / Unknown"`) to prevent parsing crashes.
- **Added Dual-Format Export:** Built the `generate_json_report` function and output formatting switcher to support structured JSON logging alongside Markdown summaries.

## 7. Which part of the final project can you confidently explain without AI assistance?
I can fully explain every line of the project codebase, including:
- How Python's `ElementTree` iterates through nested XML nodes to filter open ports.
- How the hybrid risk evaluation function evaluates static port maps before falling back to dynamic string matching.
- How structured dictionaries are compiled into the `scan_data` list and passed to respective report formatters.
- How `argparse` captures user input variables and routes execution flow based on selected format flags.
