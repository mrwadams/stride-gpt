"""VulnScope — Streamlit UI.

Upload a threat model and a batch of findings, score them, and view the
prioritised, annotated report. Run with: ``streamlit run app.py``.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import streamlit as st

# Make `import vulnscope` work when Streamlit runs this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from vulnscope.config import Config, Weights  # noqa: E402
from vulnscope.parsers.findings import parse_findings  # noqa: E402
from vulnscope.parsers.threat_model import parse_threat_model  # noqa: E402
from vulnscope.pipeline import build_client, run_analysis  # noqa: E402
from vulnscope.report import render_markdown, score_band  # noqa: E402

st.set_page_config(page_title="VulnScope", page_icon="🛡️", layout="wide")


def _save_upload(uploaded, suffix: str) -> Path:
    """Persist an uploaded file to a temp path so the stdlib parsers can read it."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp.write(uploaded.getvalue())
    tmp.close()
    return Path(tmp.name)


def _band_emoji(band: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(band, "⚪")


st.title("🛡️ VulnScope")
st.caption(
    "Threat-model-informed vulnerability finding prioritisation. "
    "Given what we know about this system, which findings actually matter?"
)

with st.sidebar:
    st.header("Configuration")
    env = Config.from_env()
    model = st.text_input(
        "Model",
        value=env.model,
        help="LiteLLM model id. Use a provider prefix for non-Anthropic models, "
        "e.g. openai/gpt-5.4, gemini/gemini-3.1-pro-preview, "
        "groq/llama-3.3-70b-versatile, mistral/mistral-large-latest, or "
        "ollama/llama3.3 (with an endpoint below).",
    )
    api_key = st.text_input(
        "API key",
        value=env.api_key or "",
        type="password",
        help="Defaults to the provider's env var (ANTHROPIC_API_KEY, "
        "OPENAI_API_KEY, ...). Leave blank to use the offline heuristic.",
    )
    api_base = st.text_input(
        "API base URL (optional)",
        value=env.api_base or "",
        help="Custom endpoint for self-hosted models (Ollama, LM Studio).",
    )
    offline = st.checkbox(
        "Offline mode (deterministic heuristic, no API calls)",
        value=False,
    )

    st.subheader("Scoring weights")
    asset = st.slider("Asset criticality", 0.0, 1.0, env.weights.asset_criticality, 0.05)
    align = st.slider("Threat alignment", 0.0, 1.0, env.weights.threat_alignment, 0.05)
    boundary = st.slider(
        "Trust boundary exposure", 0.0, 1.0, env.weights.trust_boundary_exposure, 0.05
    )
    stride = st.slider("STRIDE category weight", 0.0, 1.0, env.weights.stride_category_weight, 0.05)
    st.caption("Weights are normalised to sum to 1.0.")

col1, col2 = st.columns(2)
with col1:
    tm_file = st.file_uploader(
        "Threat model", type=["json"], help="STRIDE-GPT JSON export or minimal JSON schema."
    )
with col2:
    findings_file = st.file_uploader(
        "Findings", type=["json", "sarif"], help="SARIF v2.1.0 or a simple JSON array."
    )

run = st.button("Prioritise findings", type="primary", disabled=not (tm_file and findings_file))

if run and tm_file and findings_file:
    config = Config(
        model=model,
        api_key=api_key or None,
        api_base=api_base or None,
        offline=offline,
        weights=Weights(asset, align, boundary, stride),
    )
    try:
        tm = parse_threat_model(_save_upload(tm_file, ".json"))
        findings = parse_findings(
            _save_upload(findings_file, Path(findings_file.name).suffix or ".json")
        )
    except (ValueError, FileNotFoundError) as exc:
        st.error(f"Failed to parse inputs: {exc}")
        st.stop()

    if not findings:
        st.warning("No findings found in the uploaded file.")
        st.stop()

    try:
        client = build_client(config)
    except RuntimeError as exc:
        st.error(str(exc))
        st.stop()

    mode = "offline heuristic" if client is None else f"LLM ({config.model})"
    with st.spinner(f"Scoring {len(findings)} finding(s) using {mode}..."):
        report = run_analysis(tm, findings, config, client=client)

    st.session_state["report"] = report

report = st.session_state.get("report")
if report:
    meta = report["metadata"]
    findings = report["prioritised_findings"]

    st.success(
        f"Prioritised {meta['findings_count']} finding(s) for "
        f"**{meta['application']}**."
    )

    # Metrics
    bands = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        bands[score_band(f["composite_score"])] += 1
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🔴 Critical", bands["CRITICAL"])
    m2.metric("🟠 High", bands["HIGH"])
    m3.metric("🟡 Medium", bands["MEDIUM"])
    m4.metric("🟢 Low", bands["LOW"])

    st.subheader("Executive Summary")
    st.write(report.get("executive_summary", ""))

    st.subheader("Prioritised Findings")
    st.dataframe(
        [
            {
                "": _band_emoji(score_band(f["composite_score"])),
                "Finding": f["title"],
                "ID": f["finding_id"],
                "Score": f["composite_score"],
                "Classification": f["classification"],
                "Reasoning": f["reasoning"],
            }
            for f in findings
        ],
        use_container_width=True,
        hide_index=True,
    )

    gaps = report["threat_model_gaps"]
    if gaps:
        st.subheader("Threat Model Gaps")
        for g in gaps:
            st.markdown(f"- **{g['finding_id']}** ({g['classification']}): {g['note']}")

    st.subheader("Downloads")
    d1, d2 = st.columns(2)
    d1.download_button(
        "Download JSON report",
        data=json.dumps(report, indent=2),
        file_name="vulnscope_report.json",
        mime="application/json",
    )
    d2.download_button(
        "Download Markdown report",
        data=render_markdown(report),
        file_name="vulnscope_report.md",
        mime="text/markdown",
    )
