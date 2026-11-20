---
name: threat-model-with-stride-gpt
description: Run the stride-gpt CLI headless to produce a STRIDE threat model of a codebase (or of a written description), then read its JSON outputs correctly. Use when asked to "threat model this repo with stride-gpt", to produce STRIDE findings or SARIF for code scanning, or to check whether a stride-gpt run was complete.
---

# Threat model with stride-gpt

stride-gpt is a CLI that does the analysis itself. It plans subsystems, explores the code with
its own agent loop, and writes a report plus JSON siblings. Your job is to run it without a
human at the keyboard, then read the right file for the question you were asked.

If you want to do the STRIDE analysis yourself rather than delegate it, this is the wrong
skill. Use the `stride-threat-modelling` skill from mcp-stride-gpt instead.

## Install and keys

```bash
pip install stride-gpt
stride-gpt --version
```

The CLI reads the provider key from the environment. Set the variable for each provider you
name in `--worker-model` / `--architect-model`:

| Model prefix | Env var |
|---|---|
| `anthropic/` | `ANTHROPIC_API_KEY` |
| `openai/` (or no prefix) | `OPENAI_API_KEY` |
| `google/` | `GOOGLE_API_KEY` |
| `mistral/` | `MISTRAL_API_KEY` |
| `groq/` | `GROQ_API_KEY` |
| `deepseek/` | `DEEPSEEK_API_KEY` |
| `openrouter/` | `OPENROUTER_API_KEY` |

`STRIDE_GPT_API_KEY`, or `--worker-api-key`, overrides the worker key. The architect key comes
from its provider's env var or `--architect-api-key`. Never write a key into a file in the repo
you are analysing. If no key resolves, the CLI exits 1 before making any call and names the
variable it wanted.

Always pass `--worker-model` explicitly. Without it the CLI falls back to the user's saved
`~/.stride-gpt/config.json`, and if that doesn't exist it exits 1. The exception is a local LM
Studio model: the user sets it up once with `/config` in the interactive `stride-gpt` REPL, and
you then omit `--worker-model` so the saved config is used.

## Analyze a codebase (headless)

```bash
stride-gpt analyze <path> --yes -o <dir>/<stem>.json -f json \
  --max-llm-calls 25 \
  --worker-model anthropic/claude-sonnet-5 \
  --architect-model anthropic/claude-opus-5-5
```

- `--yes` (`-y`) is required. Without it the CLI asks for plan approval on stdin after the
  planning call, so a headless run hangs or fails there with the planning call already paid for.
- `-o` is required if you want the JSON siblings. They are only written when `-o` is given.
- Set `--max-llm-calls` explicitly so the cost ceiling is a decision, not an accident. It caps
  calls **per subsystem**. 25 is the default and about twice what a measured full run needed.
  The whole run is bounded by `subsystems × (cap + 1) + 3` calls, which the CLI prints before it
  starts. A subsystem that hits the cap still reports what it found (`budget_exhausted`).
  `0` means unlimited, so don't use it unless the user asks.
- `--app-type web|genai|agentic` overrides the planner's classification. Leave it on `auto`
  unless the user tells you what the system is.
- If a run is killed, resume it with the checkpoint written next to `-o`:
  `stride-gpt analyze <path> --yes -o <dir>/<stem>.json -f json --resume <dir>/<stem>.checkpoint.json`
  (use the same models). `--force` lets it resume when the target has uncommitted changes, so
  only pass it if you know the code hasn't changed in a way that matters.

A full run makes many LLM calls and can be expensive on frontier models. Tell the user before
starting one on a large repository.

## What gets written

With `-o out/report.json -f json`:

| File | Read it for |
|---|---|
| `out/report.findings.json` | **Threats and evidence.** `findings[]` has one entry per planned subsystem, each with `subsystem`, `outcome`, `threats[]` and `files_analyzed`. Each threat has `id`, `Threat Type`, `Scenario`, `Potential Impact` and `evidence[]`, where each evidence item is `{path, snippet, verified, start_line, end_line}`. Also `cross_cutting_threats` (emergent threats, which count) and `systemic_observations` (restatements of subsystem threats, which don't count). |
| `out/report.run.json` | **Completeness and cost.** `run_summary.status`, `subsystems_planned`, `subsystems_analyzed`, `subsystem_outcomes`, `synthesis_error_class`, `llm_calls`, `tool_calls`, and `token_usage_total` / `token_usage_by_phase` / `token_usage_by_subsystem`. Also the models used, the target's git SHA and the stride-gpt version. |
| `out/report.plan.json` | The subsystems the planner chose and the detected app type. |
| `out/report.json` | The full report as one JSON document. `-f json` also writes `out/report.html` for a human. |
| `out/report.checkpoint.json` | Resume state. Not a result. |

For code-scanning upload, run with `-o out/report.sarif -f sarif` instead. The same
`.findings.json` / `.run.json` siblings are written next to it (`out/report.findings.json`).
Each SARIF result points at the file and line range its evidence was verified at.

Paths in the siblings are redacted to `./…` or `~/…`, so they are safe to attach to a ticket.

### Evidence

A threat's evidence is checked against the file on disk. `verified: false` means the quoted
snippet wasn't found. Report those threats as unconfirmed, not as fact, and don't drop them
silently either.

## Check completeness before you report anything

Read `run_summary.status` in `<stem>.run.json` first.

**A run with `run_summary.status: partial` is incomplete, even though the CLI exited 0.** Some
subsystem crashed (`error`, see its `error_class`), returned nothing readable (`parse_failed`)
or never started because the run budget ran out (`skipped`), or synthesis failed
(`synthesis_error_class` is set). Missing threats in those subsystems mean nothing was looked at,
not that nothing was found.

When the status is `partial`:

1. Say so in the first line of your answer.
2. List which subsystems didn't finish and their `outcome`, from `findings[]` in
   `.findings.json` or `subsystem_outcomes` in `.run.json`.
3. Report the threats that were found as covering only the subsystems that finished.
4. Suggest a fix if the cause is clear: `rate_limited` or `provider_error` → rerun with
   `--resume`; `context_overflow` → a worker model with a larger context window.

`budget_exhausted` is not partial. The subsystem was analysed and reported in a final round. You
can mention that it hit the cap.

Exit codes: 0 for a completed or partial run, and also when the plan is declined. 1 when no
subsystem was analysed at all, a key is missing, the provider call fails, or the path is not a
directory. 2 for a flag misuse, such as `--architect-model` with `--no-architect`.

## When to use `quick` instead

Use `quick` when there is no code to point at: the user has a design doc, an architecture
description or an idea. It is a single short agent loop over text, so it costs far less, but no
threat cites code evidence.

```bash
stride-gpt quick -i description.md -o out/quick.md \
  --worker-model anthropic/claude-sonnet-5 \
  --architect-model anthropic/claude-opus-5-5
```

- Input comes from `-i <file>` or stdin.
- `-f` takes only `markdown` (default) or `html`. `json` or `sarif` exits 2.
- With `-o` it writes `<stem>.run.json` only, with no `.findings.json`. The structured threats
  are in the auto-saved archive under `~/.stride-gpt/reports/quick/`. Read `out/quick.md` for
  the threats.
- `--app-type` is a free-text hint here (e.g. `"Agentic AI application"`), not the `analyze`
  enum.
- There is no `--yes` and no `--max-llm-calls` on `quick`.

If there is a repository, use `analyze`. A description of code you could read is a worse input
than the code.

## Choosing worker and architect models

Decide, do not default. The worker handles the bulk of calls: per-subsystem exploration and
threat reporting. The architect is used only for planning, cross-cutting synthesis and context
summarisation. Those calls are few but decide the subsystem split and what counts as an emergent
threat. On `quick`, the architect makes the main threat-model call.

| Situation | Worker | Architect | Why |
|---|---|---|---|
| Default for a real repository | `anthropic/claude-sonnet-5` | `anthropic/claude-opus-5-5` | The worker makes most of the calls, so a fast, strong tool-calling model keeps cost down without losing evidence quality. The architect's few calls decide the plan and synthesis, so the stronger model is worth paying for there. |
| OpenAI-only key | `openai/gpt-6-sol` | `openai/gpt-6-astra` | Sol balances cost and capability for long agentic loops. Astra is the most capable OpenAI model and the architect makes few calls. |
| Google-only key | `google/gemini-3.8-flash` | `google/gemini-3.1-pro-preview` | Flash is tuned for long-horizon agentic work and is cheap per call. Pro is Google's strongest reasoning model and has a 1M context for synthesis over every finding. |
| Tight budget or first pass | `deepseek/deepseek-flash` | `--no-architect` | One cheap model for every call is enough to scope a repo. Planning and synthesis are weaker, so treat the result as a first pass and say so. |
| Large codebase, worker hitting `context_overflow` | `google/gemini-3-flash-preview` | `anthropic/claude-opus-5-5` | A fast 1M-context worker holds more files per subsystem before it has to compress. Keep a strong architect, because synthesis has more findings to reconcile. |
| Code must not leave the machine | An LM Studio model from the saved config (omit `--worker-model`) | `--no-architect` | Nothing reaches a hosted provider. Local models are weaker at tool calling, so expect more `parse_failed` and check `run_summary.status`. |
| `quick` on a description | `anthropic/claude-haiku-4-5-20251001` | `anthropic/claude-opus-5-5` | On `quick` the architect does the judgment and the worker only handles fallback and retry calls, so the cheapest worker loses nothing. |

Rules that apply to every row:

- Pick a worker that supports tool calling. A model that can't call tools can't explore or
  report threats.
- Don't use a small or "lite" model as the architect. A bad plan wastes every worker call after
  it.
- `--no-architect` makes the worker do planning and synthesis too. Use it only to save money,
  and tell the user.
- If the user names models, use them. This table is for when they don't.
