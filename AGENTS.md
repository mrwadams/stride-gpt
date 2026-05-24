# AGENTS.md

Orientation for agents (and humans) working in this codebase. Skim the whole file before starting; jump to "Progressive disclosure pattern" if you're looking to reuse that specific idea.

## What this project is

STRIDE-GPT is an AI-powered threat modelling tool that produces STRIDE reports for software systems. It ships as **two separate products** with a shared library between them:

- **CLI** (`stride_gpt/`) — the primary product. Includes an **agentic analysis engine** that explores a real codebase via filesystem tools and produces a per-subsystem STRIDE report.
- **Streamlit web UI** (`apps/web/`) — a hosted single-shot threat modeller. Takes a text description (or a GitHub URL) and produces a one-shot report. **Does not use the agentic engine**, by design — filesystem/agentic features don't fit Streamlit Community Cloud-style deployments.

Both surfaces share `stride_gpt/core/` for prompts, schemas, and the LLM abstraction.

## Repository layout

```
stride_gpt/                 # CLI package + shared library
├── cli.py                  # Typer commands + interactive REPL
├── prompt.py               # prompt_toolkit completer (slash commands)
├── config.py               # ~/.stride-gpt/config.json + provider registry
├── models.py               # model catalogue (id, default tokens, thinking support)
├── agent/                  # agentic loop (CLI-only by design)
│   ├── loop.py             # run_analysis, per-subsystem agent loop
│   ├── planner.py          # phase 1 — classify app type, propose subsystems
│   ├── context.py          # context window management + compression
│   ├── tools.py            # filesystem tools (read_file, grep, ..., load_reference)
│   ├── progress.py         # Rich-based progress callbacks
│   └── report.py           # markdown / JSON / SARIF rendering, save/load
└── core/                   # shared between CLI and web
    ├── llm.py              # unified call_llm / call_llm_with_tools via litellm
    ├── schemas.py          # LLMConfig, AnalysisPlan, AnalysisReport, etc.
    ├── prompts/
    │   ├── builder.py      # legacy single-shot prompt builder (web UI uses this)
    │   ├── variants.py     # base_system_prompt(), load_reference(), coerce_app_type()
    │   └── threat_model/   # packaged reference cards (see "Progressive disclosure")
    │       ├── base.md
    │       ├── genai.md
    │       └── agentic.md
    └── ...                 # attack_tree, dread, mitigations, test_cases, threat_model

apps/web/                   # Streamlit UI (separate product)
└── ...                     # imports from stride_gpt.core, NOT stride_gpt.agent

tests/                      # pytest, fixtures in conftest.py
```

## How the agentic analysis works

Three phases, all driven from `cli.py:analyze` (the subcommand) or `_handle_analyze` (the interactive `/analyze`):

1. **Planning** (`agent/planner.py:create_plan`) — single LLM call. Scans the codebase, classifies the application type (`web` / `genai` / `agentic`), proposes 3–7 subsystems. User approves the plan interactively (or `--yes`).
2. **Per-subsystem analysis** (`agent/loop.py:_analyze_subsystem`) — for each subsystem, a tool-using agent loop. The model reads files, greps, lists directories, and loads OWASP reference cards on demand, then emits a JSON finding. Token budget is shared across subsystems (remaining-budget arithmetic in `run_analysis`).
3. **Synthesis** (`agent/loop.py:_synthesize`) — one LLM call. Reviews all per-subsystem findings and surfaces cross-cutting threats.

Reports auto-save to `~/.stride-gpt/reports/<target>_<timestamp>.json`. The `/reports` slash command lists and re-renders saved reports.

## Progressive disclosure pattern

The agent doesn't carry every threat framework in its system prompt — that would balloon every per-subsystem call. Instead it follows the same pattern Claude Code skills use: **a small always-loaded base prompt advertises optional reference cards; the model loads them on demand via a tool.**

Current card catalogue (in `core/prompts/threat_model/`):
- `genai.md` — OWASP Top 10 for LLM Applications (LLM01–LLM10). Asset-under-attack lens for LLM-using subsystems.
- `agentic.md` — OWASP Top 10 for Agentic Applications (ASI01–ASI10). Asset-under-attack lens for agentic subsystems; loaded in addition to the genai card.
- `insider_threat.md` — AI Insider Threat framework (distilled from <https://ai-insider-threat.matt-adams.co.uk>). Agent-as-insider lens; complementary to the OWASP cards rather than alternative. Loaded for high-autonomy agentic subsystems.

### How it's wired together

Each card is a markdown file with a YAML frontmatter block describing when to load it and what schema fields it adds. The agent discovers what's available via a cheap `list_references` call (frontmatter only), then pulls the body of the cards it needs via `load_reference`.

```
┌─ Each card (e.g. genai.md) ────────────────────────────────┐
│ ---                                                        │
│ name: genai                                                │
│ title: OWASP Top 10 for LLM Applications                   │
│ when_to_load: |                                            │
│   Load when the subsystem uses LLM SDKs ...                │
│ adds_fields: [OWASP_LLM]                                   │
│ stride_letters: [S, T, R, I, D, E]                         │
│ source: https://owasp.org/...                              │
│ version: 2025                                              │
│ ---                                                        │
│                                                            │
│ # OWASP Top 10 for LLM Applications — Reference Card       │
│ (full card body — only returned by load_reference)         │
└────────────────────────────────────────────────────────────┘
                              ▲
                              │  load_reference(name="genai")
                              │
┌─ base.md (system prompt) ──┴───────────────────────────────┐
│ STRIDE framing + JSON output schema                        │
│                                                            │
│ ## Reference cards available                               │
│ Call list_references() to see the catalogue, then          │
│ load_reference(name="...") for the cards that apply.       │
└────────────────────────────────────────────────────────────┘
```

The flow per subsystem:

1. `base.md` is loaded as the system prompt for every subsystem analysis — always.
2. The planner classified the app at Phase 1; the user prompt for the subsystem includes a *hint* (`_APP_TYPE_HINTS` in `agent/loop.py`) telling the agent which cards are likely relevant.
3. The agent (optionally) calls `list_references` to see the catalogue with trigger conditions, then decides — per subsystem — whether to call `load_reference(name=...)` for each. A static-assets subsystem in an agentic codebase doesn't need the agentic card.
4. `load_reference` returns the card body (frontmatter stripped). It stays in the conversation history for the rest of that subsystem's analysis (and gets compressed away if the context window fills).
5. Each card includes schema-addition instructions (e.g. "add `OWASP_LLM` to each threat"); the renderer in `agent/report.py` surfaces those fields as conditional columns.

### Reusing this pattern in another project

The pattern is decoupled from threat modelling. The recipe:

1. **Carve out the reference content as markdown files**, one per topic. Keep each card self-contained — framing, body, any output-schema additions. The base prompt should never need to re-explain a card's contents.
2. **Put a YAML frontmatter block at the top of each card** describing when to load it, what schema fields it adds, source, and version. This metadata is the cheap discovery surface — the model reads it without paying for the whole body. See any card in `stride_gpt/core/prompts/threat_model/` for the shape.
3. **Ship two tools, not one**: `list_references` returns just the parsed frontmatter for every card (cheap discovery), `load_reference(name=...)` returns the body for a specific card (heavy payload). Both implementations are packaged-data lookups — `importlib.resources.files(...).read_text()`. See `stride_gpt/core/prompts/variants.py` for the discovery + loader, and `stride_gpt/agent/tools.py` for the tool definitions + dispatch. `load_reference` returns an error string for unknown names; the model recovers gracefully.
4. **Package the markdown files as data** in `pyproject.toml`:
   ```toml
   [tool.setuptools.package-data]
   "your_pkg.cards" = ["*.md"]
   ```
   And make the cards directory a real package (`__init__.py` present) so `find_packages` discovers it — otherwise package-data silently no-ops and the wheel ships without the files.
5. **Optionally seed the agent with a hint** from earlier-phase work (here, the planner). The hint goes in the *user* message, not the system prompt — that keeps the base prompt static and lets each turn carry its own context.
6. **Render any per-card schema additions conditionally** — only show the column if at least one item in the report carries the field. See `agent/report.py:_detect_owasp_columns` and `_threat_table_header`.

### When this pattern is the right fit

- You have multiple "modes" or "frameworks" where loading them all up front would be wasteful.
- The selection rule isn't strictly deterministic — different parts of the same job may want different references.
- You want analysts (not just engineers) to be able to edit the reference content.

### When it's not

- Two or three short branches with a clear deterministic split — just compose the prompt eagerly, you're doing option-2 with extra steps.
- The reference content is small enough that loading all of it costs negligibly.
- The model can't be trusted to make the selection (older / smaller models often won't call optional tools without strong nudging).

## LLM provider abstraction

Everything goes through `stride_gpt/core/llm.py` — `call_llm`, `call_llm_with_tools`, `call_llm_with_image`. Under the hood these use `litellm.completion` with provider-aware kwargs assembled in `_build_litellm_kwargs`. **Never call `litellm.completion` directly** from outside `core/llm.py` — that's how provider-specific quirks leak across the codebase.

Models are registered in `stride_gpt/models.py` with provider, default tokens, max tokens, and capability flags (`supports_thinking`, etc.).

### Provider gotchas

- **Gemini does NOT accept the Anthropic-shaped `thinking={"type": "enabled", ...}` kwarg.** litellm rejects it for newer models (e.g. `gemini-3.1-flash-lite`). Thinking-capable Gemini models have thinking on by default and surface it via `thinking_blocks` on the response. Don't send the kwarg.
- **Anthropic with `use_thinking=True` requires `max_tokens > budget_tokens`.** `_build_litellm_kwargs` enforces 48000 as the floor when thinking is on.
- **GPT-5 series uses `max_completion_tokens`, not `max_tokens`.** Driven off `model_uses_completion_tokens` in the model registry.
- **LM Studio only accepts `json_schema` or `text` response_format**, not `json_object`. Branch in `_build_litellm_kwargs`.
- **Groq DeepSeek emits `<think>` tags inline.** Extracted by `extract_deepseek_reasoning`.

When adding a new provider or model, the kwarg shape almost always needs a new branch in `_build_litellm_kwargs`. Don't try to make it generic — provider quirks are real and pretending they aren't causes silent bugs.

## Adding a feature — orientation

- **Prompt changes that affect both the agent and the legacy single-shot path** → edit the markdown reference cards. Section helpers in `core/prompts/builder.py` already load from them.
- **A new agent capability** → typically a new tool in `agent/tools.py` (add to `AGENT_TOOLS` list + `_TOOL_DISPATCH` dict + the test in `test_tools.py:TestToolDefinitions:test_tool_names_match_dispatch`).
- **A new output format** → add a renderer in `agent/report.py`, wire it into `cli.py:analyze` via the `OutputFormat` enum, add a from-JSON variant if it should work for saved reports.
- **A new threat-model "lens"** (e.g. cloud-specific, IoT) → drop a new markdown card under `core/prompts/threat_model/` with a YAML frontmatter block (see existing cards for shape: `name`, `title`, `when_to_load`, `adds_fields`, `stride_letters`, `source`, `version`). Discovery picks it up automatically via `list_references` — no edits to `variants.py` or `tools.py` required. Still hand-maintained: the per-card pointer block in `base.md` (the agent reads it upfront and so doesn't always need a discovery call) and the card catalogue list under "Progressive disclosure pattern" above. If the card declares a new field in `adds_fields`, also extend `_detect_extra_columns` / `_threat_table_header` / `_threat_table_row` in `agent/report.py` so the field renders. The planner classifier only needs a new app-type value if the card should auto-trigger; otherwise the agent decides per subsystem based on each card's `when_to_load`. See the `insider_threat` card for a worked example.

## Testing

- pytest, runs in ~1.5s. `pytest -q` from the repo root.
- Fixtures live in `tests/conftest.py`. `llm_config` gives a fake `LLMConfig`; `sandbox_dir` builds a small fake project tree; `sample_plan` / `sample_finding` / `sample_report` provide canned `AnalysisReport` data.
- LLM calls are always mocked. The canonical pattern: `@patch("stride_gpt.agent.loop.call_llm_with_tools")` and feed `LLMResponse(content=..., tool_calls=...)`. End-to-end agent-loop tests in `test_loop.py:TestAppTypeFlow` mock multiple turns by setting `side_effect=[turn1, turn2, ...]`.
- For prompt content tests (`test_variants.py`), assert structural properties (a code is present, a column is rendered) — not exact text. Markdown content changes; structural assertions don't.

## A few things to NOT do

- **Don't bypass `core/llm.py`.** It exists to make provider quirks one team's problem.
- **Don't add the agentic engine to the web UI.** It was explicitly removed — see the project memory. The web UI is for hosted deployments that can't run filesystem-touching code.
- **Don't drift the agent's reference cards from the legacy `create_threat_model_prompt` path.** Both consume the same markdown files via `load_reference`; keep it that way.
- **Don't make the planner deterministic via grep heuristics.** The planner LLM is trusted to classify app type — the resulting hint is just a hint, the agent can override per subsystem.
