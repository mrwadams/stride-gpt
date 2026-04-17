"""Deep Analysis tab for the Streamlit UI.

Integrates the agentic analysis engine (agent loop) into the Streamlit frontend,
providing a multi-step flow: Input → Plan Review → Running → Results.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from pathlib import Path

import streamlit as st

from stride_gpt.agent.planner import format_plan_for_display
from stride_gpt.agent.progress import QueueProgress
from stride_gpt.core.schemas import AnalysisPlan, AnalysisReport
from stride_gpt.streamlit_utils import build_llm_config_from_session, clone_github_repo


def render_deep_analysis_tab() -> None:
    """Render the Deep Analysis tab content."""
    st.markdown(
        """
Use the agentic analysis engine to perform a deep STRIDE threat model of a codebase.
The agent will explore the code using filesystem tools, plan its analysis across subsystems,
and produce a comprehensive threat report with cross-cutting findings.
"""
    )
    st.markdown("---")

    # Initialize state
    if "deep_analysis_step" not in st.session_state:
        st.session_state["deep_analysis_step"] = 0

    step = st.session_state["deep_analysis_step"]

    if step == 0:
        _render_input_step()
    elif step == 1:
        _render_plan_step()
    elif step == 2:
        _render_running_step()
    elif step == 3:
        _render_results_step()


def _render_input_step() -> None:
    """Step 0: Collect target path or GitHub URL."""
    st.subheader("Target")

    input_mode = st.radio(
        "How would you like to provide the codebase?",
        ["Local directory", "GitHub repository"],
        horizontal=True,
        key="deep_analysis_input_mode",
    )

    if input_mode == "Local directory":
        target_path = st.text_input(
            "Directory path (absolute):",
            placeholder="/path/to/your/project",
            key="deep_analysis_path",
            help="Enter the full absolute path to the codebase directory (e.g. /home/user/myproject). Use ~ for your home directory.",
        )
    else:
        target_path = st.text_input(
            "GitHub URL:",
            placeholder="https://github.com/owner/repo",
            key="deep_analysis_github_url",
        )

    col1, col2 = st.columns(2)
    with col1:
        max_llm = st.number_input(
            "Max LLM calls (0 = unlimited):",
            min_value=0,
            value=0,
            step=5,
            key="deep_analysis_max_llm",
            help="Hard limit on total LLM API calls. 0 means no limit.",
        )
    with col2:
        max_tools = st.number_input(
            "Max tool calls (0 = unlimited):",
            min_value=0,
            value=0,
            step=10,
            key="deep_analysis_max_tools",
            help="Hard limit on filesystem tool executions. 0 means no limit.",
        )

    st.markdown("")

    if st.button("Scan & Plan", type="primary", use_container_width=True):
        if not target_path:
            st.error("Please provide a directory path or GitHub URL.")
            return

        # Validate config
        try:
            config = build_llm_config_from_session()
        except Exception as e:
            st.error(f"Configuration error: {e}")
            return

        if not config.api_key and config.provider not in ("Ollama", "LM Studio Server"):
            st.error("Please configure your API key in the sidebar first.")
            return

        if not config.model_name:
            st.error("Please select a model in the sidebar first.")
            return

        # Resolve target
        if input_mode == "GitHub repository":
            with st.spinner("Cloning repository..."):
                try:
                    resolved = clone_github_repo(target_path)
                except ValueError as e:
                    st.error(str(e))
                    return
        else:
            expanded = Path(target_path).expanduser()
            if not expanded.is_absolute():
                st.error("Please enter an absolute path (e.g. /home/user/project or ~/project).")
                return
            resolved = expanded.resolve()
            if not resolved.is_dir():
                st.error(f"Directory not found: {resolved}")
                return

        # Generate plan
        with st.spinner("Scanning codebase and generating analysis plan..."):
            try:
                from stride_gpt.agent.loop import create_analysis_plan

                plan = create_analysis_plan(config, resolved)
            except Exception as e:
                st.error(f"Planning failed: {e}")
                return

        # Store state and advance
        st.session_state["deep_analysis_plan"] = plan
        st.session_state["deep_analysis_target"] = str(resolved)
        st.session_state["deep_analysis_config"] = config
        st.session_state["deep_analysis_step"] = 1
        st.rerun()


def _render_plan_step() -> None:
    """Step 1: Display plan for user approval."""
    plan: AnalysisPlan = st.session_state["deep_analysis_plan"]

    st.subheader("Analysis Plan")
    st.markdown(
        f"**Target:** `{st.session_state['deep_analysis_target']}`\n\n"
        f"**Description:** {plan.overall_description}"
    )

    st.markdown("### Subsystems to Analyze")
    for i, sub in enumerate(plan.subsystems, 1):
        with st.expander(f"{i}. {sub.name}", expanded=i <= 3):
            st.markdown(sub.description)
            if sub.key_files:
                st.markdown("**Key files:** " + ", ".join(f"`{f}`" for f in sub.key_files))
            if sub.focus_areas:
                st.markdown("**Focus areas:** " + ", ".join(sub.focus_areas))

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Approve & Run Analysis", type="primary", use_container_width=True):
            st.session_state["deep_analysis_step"] = 2
            st.session_state["deep_analysis_events"] = []
            st.rerun()
    with col2:
        if st.button("Cancel", use_container_width=True):
            _reset_state()
            st.rerun()


def _render_running_step() -> None:
    """Step 2: Run analysis in background thread with progress updates."""
    # Start thread if not already running
    if "deep_analysis_thread" not in st.session_state or not st.session_state["deep_analysis_thread"].is_alive():
        if "deep_analysis_report" in st.session_state:
            # Thread finished between reruns — advance to results
            st.session_state["deep_analysis_step"] = 3
            st.rerun()
            return

        if "deep_analysis_thread" not in st.session_state:
            # First entry — launch the thread
            event_queue: queue.Queue = queue.Queue()
            st.session_state["deep_analysis_queue"] = event_queue

            config = st.session_state["deep_analysis_config"]
            plan = st.session_state["deep_analysis_plan"]
            target = Path(st.session_state["deep_analysis_target"])
            max_llm = st.session_state.get("deep_analysis_max_llm", 0)
            max_tools = st.session_state.get("deep_analysis_max_tools", 0)

            def _run():
                from stride_gpt.agent.loop import run_analysis

                progress = QueueProgress(event_queue)
                try:
                    report = run_analysis(
                        config=config,
                        target_path=target,
                        plan=plan,
                        max_llm_calls=max_llm,
                        max_tool_calls=max_tools,
                        progress=progress,
                    )
                    event_queue.put({"type": "finished", "report": report})
                except Exception as e:
                    event_queue.put({"type": "fatal_error", "message": str(e)})

            thread = threading.Thread(target=_run, daemon=True)
            st.session_state["deep_analysis_thread"] = thread
            thread.start()

    # Drain events from queue
    event_queue = st.session_state.get("deep_analysis_queue")
    events: list[dict] = st.session_state.get("deep_analysis_events", [])

    if event_queue:
        while True:
            try:
                event = event_queue.get_nowait()
                events.append(event)
            except queue.Empty:
                break
        st.session_state["deep_analysis_events"] = events

    # Check for completion
    report = None
    fatal_error = None
    for event in events:
        if event["type"] == "finished":
            report = event["report"]
        elif event["type"] == "fatal_error":
            fatal_error = event["message"]

    if report is not None:
        st.session_state["deep_analysis_report"] = report
        st.session_state["deep_analysis_step"] = 3
        # Clean up thread state
        st.session_state.pop("deep_analysis_thread", None)
        st.session_state.pop("deep_analysis_queue", None)
        st.rerun()
        return

    if fatal_error is not None:
        st.error(f"Analysis failed: {fatal_error}")
        st.session_state.pop("deep_analysis_thread", None)
        st.session_state.pop("deep_analysis_queue", None)
        if st.button("Back to Input"):
            _reset_state()
            st.rerun()
        return

    # Render progress
    plan: AnalysisPlan = st.session_state["deep_analysis_plan"]
    total_subsystems = len(plan.subsystems)

    # Find current state from events
    current_phase = "Starting..."
    subsystems_done = 0
    current_subsystem = ""
    tool_calls: list[dict] = []

    for event in events:
        etype = event["type"]
        if etype == "phase_start":
            current_phase = f"{event['phase']}: {event['description']}"
        elif etype == "subsystem_start":
            current_subsystem = event["name"]
        elif etype == "subsystem_done":
            subsystems_done += 1
        elif etype == "tool_call":
            tool_calls.append(event)
        elif etype == "error":
            subsystems_done += 1

    st.subheader("Analysis in Progress")

    # Progress bar
    progress_pct = subsystems_done / total_subsystems if total_subsystems else 0
    st.progress(progress_pct, text=current_phase)

    # Status summary
    st.markdown(f"**Subsystems:** {subsystems_done}/{total_subsystems} complete")
    if current_subsystem and subsystems_done < total_subsystems:
        st.markdown(f"**Currently analyzing:** {current_subsystem}")

    # Per-subsystem results so far
    for event in events:
        if event["type"] == "subsystem_done":
            st.success(f"{event['name']}: {event['threat_count']} threats found")
        elif event["type"] == "error":
            st.error(f"{event['name']}: {event['reason']}")

    # Tool call log
    if tool_calls:
        with st.expander(f"Tool calls ({len(tool_calls)})", expanded=False):
            for tc in tool_calls[-30:]:  # Show last 30
                cached = " (cached)" if tc.get("cached") else ""
                st.text(f"{tc['name']}({tc['args_brief']}){cached}")

    # Auto-refresh while running
    time.sleep(1)
    st.rerun()


def _render_results_step() -> None:
    """Step 3: Display analysis results with download options."""
    report: AnalysisReport = st.session_state["deep_analysis_report"]

    st.subheader("Analysis Results")

    # Summary metrics
    total_threats = sum(len(f.threats) for f in report.findings) + len(report.cross_cutting_threats or [])
    succeeded = sum(1 for f in report.findings if f.threats)
    meta = report.metadata or {}

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Threats", total_threats)
    col2.metric("Subsystems Analyzed", meta.get("subsystems_analyzed", len(report.findings)))
    col3.metric("LLM Calls", meta.get("llm_calls", "N/A"))
    col4.metric("Tool Calls", meta.get("tool_calls", "N/A"))

    st.markdown("---")

    # Per-subsystem findings
    st.markdown("### Subsystem Findings")
    for finding in report.findings:
        threat_count = len(finding.threats)
        icon = "+" if threat_count > 0 else "-"
        with st.expander(f"{finding.subsystem} ({threat_count} threats)", expanded=threat_count > 0):
            if finding.files_analyzed:
                st.markdown("**Files analyzed:** " + ", ".join(f"`{f}`" for f in finding.files_analyzed))

            if finding.threats:
                for threat in finding.threats:
                    threat_type = threat.get("Threat Type", "Unknown")
                    scenario = threat.get("Scenario", "")
                    impact = threat.get("Potential Impact", "")
                    st.markdown(
                        f"**{threat_type}**\n\n"
                        f"{scenario}\n\n"
                        f"*Impact: {impact}*"
                    )
                    st.markdown("---")
            else:
                st.info("No threats identified for this subsystem.")

            if finding.improvement_suggestions:
                st.markdown("**Recommendations:**")
                for suggestion in finding.improvement_suggestions:
                    st.markdown(f"- {suggestion}")

    # Cross-cutting threats
    if report.cross_cutting_threats:
        st.markdown("### Cross-Cutting Threats")
        for threat in report.cross_cutting_threats:
            threat_type = threat.get("Threat Type", "Unknown")
            scenario = threat.get("Scenario", "")
            impact = threat.get("Potential Impact", "")
            affected = threat.get("Affected Subsystems", [])
            st.markdown(
                f"**{threat_type}**\n\n"
                f"{scenario}\n\n"
                f"*Impact: {impact}*\n\n"
                f"*Affects: {', '.join(affected)}*"
            )
            st.markdown("---")

    # Downloads
    st.markdown("### Export")

    from stride_gpt.agent.report import render_json, render_markdown, render_sarif

    md_report = render_markdown(report)
    json_report = json.dumps(render_json(report), indent=2)
    sarif_report = json.dumps(render_sarif(report), indent=2)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.download_button(
            "Download Markdown",
            data=md_report,
            file_name="stride_threat_model.md",
            mime="text/markdown",
            use_container_width=True,
        )
    with col2:
        st.download_button(
            "Download JSON",
            data=json_report,
            file_name="stride_threat_model.json",
            mime="application/json",
            use_container_width=True,
        )
    with col3:
        st.download_button(
            "Download SARIF",
            data=sarif_report,
            file_name="stride_threat_model.sarif",
            mime="application/json",
            use_container_width=True,
        )

    st.markdown("")
    if st.button("New Analysis", use_container_width=True):
        _reset_state()
        st.rerun()


def _reset_state() -> None:
    """Clear all deep analysis session state."""
    keys_to_remove = [
        "deep_analysis_step",
        "deep_analysis_plan",
        "deep_analysis_target",
        "deep_analysis_config",
        "deep_analysis_report",
        "deep_analysis_events",
        "deep_analysis_thread",
        "deep_analysis_queue",
    ]
    for key in keys_to_remove:
        st.session_state.pop(key, None)
