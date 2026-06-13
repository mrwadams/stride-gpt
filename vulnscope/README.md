# VulnScope

**Threat-model-informed vulnerability finding prioritisation.**

AI vulnerability finders now produce findings faster than teams can remediate
them. The missing layer is *relevance to the specific system*: a buffer overflow
in a logging library is not equally critical in every architecture. VulnScope
consumes a threat model (the system's trust boundaries, high-value assets, STRIDE
categories, and DREAD scores) alongside a batch of vulnerability findings, and
produces a prioritised, annotated report that answers: **given what we know about
this system, which of these findings actually matter, and why?**

It is a companion to [STRIDE-GPT](https://github.com/mrwadams/stride-gpt) — point
it at a STRIDE-GPT JSON export and a scanner's SARIF output, and it ranks the
findings by how much they matter to *your* architecture.

---

## How it works

For each finding, an LLM scores four dimensions (0–10) using the threat model as
context:

| Dimension | Weight | Question |
|---|---|---|
| **Asset Criticality** | 35% | Does it affect a high-value or external-facing component? |
| **Threat Alignment** | 30% | Does it corroborate a threat the model already identified? |
| **Trust Boundary Exposure** | 25% | Is the component on/near a trust boundary? |
| **STRIDE Category Weight** | 10% | How high is the aggregate DREAD for this STRIDE category? |

The **composite score** is the weighted average. Each finding also gets a
secondary classification:

- `CORROBORATED` — directly validates an existing threat model threat.
- `NOVEL` — affects a modelled component, but a category the model doesn't cover
  (flag for a threat model update).
- `OUT_OF_SCOPE` — affects a component not present in the threat model at all.

---

## Installation

```bash
cd vulnscope
pip install -r requirements.txt
```

Requires Python 3.11+.

Set your Anthropic API key (or use `--offline`, below):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## CLI usage

```bash
# SARIF findings (Semgrep, CodeQL, Snyk, XBOW, ZeroPath, ...)
python cli.py --threat-model tm.json --findings results.sarif

# Simple JSON findings
python cli.py --threat-model tm.json --findings results.json -o out/report

# No API key? Use the deterministic offline heuristic.
python cli.py -t tm.json -f results.sarif --offline
```

This writes two reports — `<prefix>.json` (machine-readable, CI/CD friendly) and
`<prefix>.md` (human-readable) — and prints a console summary:

```
VulnScope — 42 findings processed against ThreatModel: PaymentAPI

  CRITICAL  (8.0–10.0): 3 findings
  HIGH      (6.0–7.9):  8 findings
  MEDIUM    (4.0–5.9): 19 findings
  LOW       (0–3.9):   12 findings

  Corroborated: 18  |  Novel: 11  |  Out of scope: 13

  Top finding: SQL injection in UserService [score: 9.1, CORROBORATED]
```

### Useful flags

| Flag | Default | Purpose |
|---|---|---|
| `-t, --threat-model` | — | Threat model file (required) |
| `-f, --findings` | — | Findings file (required) |
| `-o, --output` | `vulnscope_report_<date>` | Output path prefix |
| `--model` | `claude-sonnet-4-6` | Anthropic model id |
| `--api-key` | `$ANTHROPIC_API_KEY` | API key |
| `--offline` | off | Score with the heuristic, no API calls |
| `--asset-weight` / `--align-weight` / `--boundary-weight` / `--stride-weight` | 0.35 / 0.30 / 0.25 / 0.10 | Override scoring weights |

Weights are normalised to sum to 1.0, so you can adjust a subset freely.

---

## Streamlit UI

```bash
streamlit run app.py
```

Upload a threat model and a findings file, tune the weights in the sidebar, and
view the prioritised table, executive summary, and threat model gaps. Download
the JSON or markdown report from the page.

---

## Docker

```bash
docker build -t vulnscope .

# Streamlit UI on http://localhost:8501
docker run --rm -p 8501:8501 -e ANTHROPIC_API_KEY vulnscope

# CLI in the same image
docker run --rm -v "$PWD:/data" --entrypoint python vulnscope \
  cli.py -t /data/tm.json -f /data/results.sarif -o /data/report --offline
```

---

## Input formats

### Threat model (one of)

1. **STRIDE-GPT JSON export** (preferred) — the `-f json` report from
   `stride-gpt analyze`. Detected by its `subsystems` array.
2. **Minimal hand-rolled schema** — for users without STRIDE-GPT:

   ```json
   {
     "application_name": "PaymentAPI",
     "components": [
       { "name": "UserService", "description": "...", "trust_zone": "dmz" }
     ],
     "data_flows": [
       { "from": "UserService", "to": "Database",
         "data_types": ["PII"], "crosses_trust_boundary": true }
     ],
     "threats": [
       { "id": "TM-014", "stride_category": "Tampering",
         "component": "UserService", "description": "...", "dread_score": 7.2 }
     ]
   }
   ```

   `trust_zone` is one of `internal | external | dmz`. `id` is optional —
   VulnScope assigns `TM-001`, `TM-002`, … to any threat without one.

> STRIDE-GPT **markdown** export parsing is planned for v1.1; export as JSON
> (one click) in the meantime.

### Findings (one of)

1. **SARIF v2.1.0** — the industry standard emitted by most scanners. VulnScope
   reads the rule metadata, CWE taxa/tags, `security-severity`, and the affected
   component (logical location, else file path).
2. **Simple JSON array**:

   ```json
   [
     {
       "id": "FINDING-001",
       "title": "SQL injection in /api/users endpoint",
       "severity": "HIGH",
       "component": "UserService",
       "description": "...",
       "cwe": "CWE-89"
     }
   ]
   ```

---

## Output: prioritised JSON

```jsonc
{
  "metadata": { "application": "...", "findings_count": 42, "generated_at": "..." },
  "executive_summary": "...",
  "prioritised_findings": [
    {
      "finding_id": "FINDING-001",
      "title": "...",
      "composite_score": 8.4,
      "classification": "CORROBORATED",
      "scores": { "asset_criticality": 9, "threat_alignment": 8,
                  "trust_boundary_exposure": 8, "stride_category_weight": 7 },
      "reasoning": "... cites TM-014 / UserService / Tampering ...",
      "original_finding": { /* the source finding, verbatim */ }
    }
  ],
  "threat_model_gaps": [
    { "finding_id": "FINDING-017", "classification": "OUT_OF_SCOPE", "note": "..." }
  ]
}
```

### CI/CD integration

VulnScope's JSON is designed for pipelines. A common pattern (not built into v1,
but a one-liner to wire up): run your scanner, run VulnScope on the SARIF, then
fail the build if any finding lands in the `CRITICAL` band.

```bash
python cli.py -t tm.json -f scan.sarif -o report
python - <<'PY'
import json, sys
r = json.load(open("report.json"))
crit = [f for f in r["prioritised_findings"] if f["composite_score"] >= 8.0]
sys.exit(1 if crit else 0)
PY
```

---

## Configuration

| Environment variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Required for LLM scoring |
| `VULNSCOPE_MODEL` | `claude-sonnet-4-6` | Default model |
| `VULNSCOPE_ASSET_WEIGHT` | `0.35` | Asset criticality weight |
| `VULNSCOPE_ALIGN_WEIGHT` | `0.30` | Threat alignment weight |
| `VULNSCOPE_BOUNDARY_WEIGHT` | `0.25` | Trust boundary exposure weight |
| `VULNSCOPE_STRIDE_WEIGHT` | `0.10` | STRIDE category weight |

---

## Offline mode

`--offline` (or simply having no API key) scores with a deterministic heuristic
instead of the LLM. It matches findings to threat model components and threats,
maps CWEs to STRIDE categories, and weights by trust zone, boundary crossings,
and aggregate DREAD. Its reasoning still cites real threat model elements, so the
tool stays fully usable — and demonstrable — without credentials. The LLM path
produces richer, more nuanced reasoning; the heuristic is a faithful, transparent
fallback.

---

## Development

```bash
pip install -r requirements.txt
pytest tests/
```

---

## Notes & roadmap

- **v1.0 (this release):** CLI + Streamlit, STRIDE-GPT JSON & minimal-schema
  threat models, SARIF & simple-JSON findings, Claude scoring (Anthropic SDK)
  with an offline heuristic, JSON + markdown + console output, Docker.
- **Planned (v1.1):** STRIDE-GPT markdown parsing; multi-provider LLM support
  (OpenAI, Gemini, Ollama) using the same pattern as STRIDE-GPT/AttackGen.

SARIF is parsed with the standard library rather than a third-party reader: the
subset we need (results, rules, locations, CWE taxa) is small and stable, and a
dependency-free parser is more robust across the many scanner dialects.
