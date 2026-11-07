#!/usr/bin/env bash
# Install a built wheel into a clean venv and smoke-test it. CI runs this on
# every push, and release.yml runs it on the wheel it is about to publish.
#
# Usage: scripts/smoke_wheel.sh dist/stride_gpt-X.Y.Z-py3-none-any.whl
#
# Tests run against the source tree, so a file that setuptools leaves out of
# the wheel (package-data only lists *.md in threat_model/) still passes them.
# The wheel goes into an empty venv and runs from outside the checkout, so
# nothing can import from the source tree.
set -euo pipefail

wheel="$(realpath "$1")"
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
venv="$work/wheel-venv"

# --no-config drops [tool.uv]: its lock-only filelock>=4.2.1 floor holds
# litellm at 1.103 (litellm >=1.104 requires filelock<4), while
# `pip install stride-gpt` resolves the newest release (#330). The cooldown is
# re-applied by hand and mirrors [tool.uv] exclude-newer.
uv venv "$venv" --python 3.12
uv pip install --no-config --exclude-newer "5 days" \
  --python "$venv/bin/python" "$wheel"

cd "$work"
"$venv/bin/stride-gpt" --version
"$venv/bin/stride-gpt" --help > /dev/null
CARDS_SRC="$repo/stride_gpt/core/prompts/threat_model" "$venv/bin/python" - <<'PY'
import os
import pathlib

import stride_gpt
from importlib.resources import files
from stride_gpt.core.prompts.variants import list_references

assert "site-packages" in stride_gpt.__file__, stride_gpt.__file__
src = {p.name for p in pathlib.Path(os.environ["CARDS_SRC"]).glob("*.md")}
pkg = {f.name for f in files("stride_gpt.core.prompts.threat_model").iterdir()}
missing = sorted(src - pkg)
assert not missing, f"missing from wheel: {missing}"
assert list_references(), "no reference cards found in the installed package"
print(f"{len(src)} prompt files packaged, {len(list_references())} reference cards")

# Every subsystem's tool loop passes tools to litellm.completion(), and
# litellm imports optional packages on that path (mcp from 1.106.0).
# mock_response keeps it offline; core/llm.py has no hook for that.
import litellm
from importlib.metadata import version

tool = {"type": "function", "function": {
    "name": "noop", "description": "noop",
    "parameters": {"type": "object", "properties": {}}}}
litellm.completion(
    model="openai/smoke", api_key="unused", mock_response="ok",
    messages=[{"role": "user", "content": "hi"}], tools=[tool],
)
print(f"tool-calling completion ok on litellm {version('litellm')}")
PY
