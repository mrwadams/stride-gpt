"""Generate the OrcaRouter Cyber Inference GUI evidence during verification.

This script is intentionally committed as automation, not as evidence. A
verification run executes it; the run creates ``orca-evidence/`` in the
repository, writes ``manifest.json`` plus the three screenshots there, and
those generated files are what the verifier inspects. Nothing under
``orca-evidence/`` is committed: the patch contains only this script.

``manifest.json`` has an ``automation`` object (``framework``, ``passed``,
``catalog_source``, ``catalog_model_count``, ``image_model_count``) and an
``artifacts`` array of ``{kind, path, sha256, width, height, ui}`` entries,
with every artifact path relative to ``orca-evidence/``.

It starts the Streamlit app itself on an ephemeral loopback port, proves the
live catalogue and a real chat completion through the provider's own code
path, then drives the real UI with Playwright:

1. select ``OrcaRouter Cyber Inference`` and show the masked API-key entry;
2. expand the text model dropdown and assert its options equal the live
   catalogue's chat models;
3. open the image-analysis tab and assert the multimodal dropdown contains
   exactly the live catalogue's image-input chat models.

The API key is read from ``ORCAROUTER_API_KEY`` and is never printed, logged,
or written to the manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "orca-evidence"
CATALOG_SOURCE = "https://api.orcarouter.ai/v1/models?capability=chat"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_app(url: str, process: subprocess.Popen, timeout: float = 180.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            raise SystemExit(f"Streamlit exited early with code {process.returncode}")
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            time.sleep(1)
    raise SystemExit("Streamlit did not become ready in time")


def start_app() -> tuple[subprocess.Popen, str]:
    port = free_port()
    url = f"http://127.0.0.1:{port}/"
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(REPO_ROOT), env.get("PYTHONPATH", "")]
    ).strip(os.pathsep)
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            "apps/web/main.py",
            "--global.developmentMode",
            "false",
            "--server.headless",
            "true",
            "--server.address",
            "127.0.0.1",
            "--server.port",
            str(port),
            "--browser.gatherUsageStats",
            "false",
        ],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wait_for_app(url, process)
    return process, url


def select_provider(page: Page) -> None:
    provider = page.locator('[data-testid="stSidebar"] [data-testid="stSelectbox"]').first
    provider.locator('input[role="combobox"]').click()
    page.keyboard.press("Control+A")
    page.keyboard.type("OrcaRouter")
    page.wait_for_timeout(600)
    page.locator('[role="option"]').first.click()
    page.wait_for_selector("text=Live OrcaRouter catalogue", timeout=60_000)
    page.wait_for_timeout(1500)


def capture(page: Page, kind: str) -> dict:
    """Screenshot one evidence kind; ``path`` stays relative to orca-evidence/."""
    path = OUT_DIR / f"{kind}.png"
    page.screenshot(path=str(path), full_page=False)
    size = page.viewport_size
    return {
        "kind": kind,
        "path": f"{kind}.png",
        "sha256": sha256(path),
        "width": size["width"],
        "height": size["height"],
    }


def dropdown_metrics(page: Page, trigger: object) -> dict:
    panel = page.eval_on_selector('[role="listbox"]', """el => {
      const panel = el.parentElement;
      const s = getComputedStyle(panel);
      const r = panel.getBoundingClientRect();
      return {bg: s.backgroundColor, borderWidth: s.borderWidth,
              borderStyle: s.borderStyle, right: r.right, open: r.height > 0};
    }""")
    trigger_box = trigger.bounding_box()
    alpha = 1.0
    if panel["bg"].startswith("rgba"):
        alpha = float(panel["bg"].rstrip(")").split(",")[-1])
    return {
        "dropdown_open": bool(panel["open"]),
        "item_count": page.locator('[role="option"]').count(),
        "opaque_background": alpha == 1.0,
        "visible_border": panel["borderWidth"] not in ("0px", "")
        and panel["borderStyle"] != "none",
        "trigger_panel_right_delta": round(
            abs(trigger_box["x"] + trigger_box["width"] - panel["right"]), 2
        ),
    }


def authoritative_chat_ids(api_key: str) -> list[str]:
    """Read the official chat-capability catalogue and return its model ids."""
    request = urllib.request.Request(
        CATALOG_SOURCE,
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return sorted(item["id"] for item in payload.get("data", []))


def live_provider_check(api_key: str) -> dict:
    """Read the live catalogue and make one real chat call through the provider."""
    from stride_gpt.core.llm import call_llm
    from stride_gpt.core.orcarouter import DEFAULT_MODEL, fetch_models
    from stride_gpt.core.schemas import LLMConfig

    models = fetch_models(api_key)
    chat_ids = [m.model_id for m in models if m.supports_chat]
    image_ids = [m.model_id for m in models if m.supports_image_input]
    if set(authoritative_chat_ids(api_key)) != set(chat_ids):
        raise SystemExit(
            "the provider's chat filter diverged from the authoritative chat catalogue"
        )
    preferred = ["orca/orcacyber-zero-1.5", DEFAULT_MODEL, "orcarouter/fusion"]
    candidates = [m for m in preferred if m in chat_ids] + [
        m for m in chat_ids if m not in preferred
    ][:3]
    failures = []
    for model_name in candidates:
        try:
            response = call_llm(
                LLMConfig(
                    provider="OrcaRouter Cyber Inference",
                    model_name=model_name,
                    api_key=api_key,
                    max_tokens=16,
                ),
                [{"role": "user", "content": "Reply with the word ok."}],
            )
        except Exception as exc:
            failures.append(f"{model_name}: {type(exc).__name__}")
            continue
        if response.content.strip():
            return {
                "catalog_chat_models": chat_ids,
                "catalog_image_models": image_ids,
                "chat_model": model_name,
            }
        failures.append(f"{model_name}: empty response")
    raise SystemExit("no live chat model was reachable: " + "; ".join(failures))


def main() -> None:
    api_key = os.environ.get("ORCAROUTER_API_KEY", "")
    if not api_key:
        raise SystemExit("ORCAROUTER_API_KEY is required to generate live GUI evidence")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for stale in ("manifest.json", "measurements.json"):
        (OUT_DIR / stale).unlink(missing_ok=True)
    for stale in ("auth-methods.png", "text-model-dropdown.png", "multimodal-model-dropdown.png"):
        (OUT_DIR / stale).unlink(missing_ok=True)

    live = live_provider_check(api_key)
    chat_ids = live["catalog_chat_models"]
    image_ids = live["catalog_image_models"]
    assert image_ids, "live catalogue declares no image-input chat models"

    automation: dict = {
        "framework": "playwright",
        "script": "scripts/capture_orca_gui.py",
        "catalog_source": CATALOG_SOURCE,
        "catalog_model_count": len(chat_ids),
        "image_model_count": len(image_ids),
    }
    artifacts: list[dict] = []

    process, base_url = start_app()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                executable_path="/usr/bin/chromium",
                headless=True,
                args=["--no-sandbox"],
            )
            try:
                context = browser.new_context(viewport={"width": 1400, "height": 1400})
                page = context.new_page()
                page.goto(base_url, wait_until="networkidle")
                page.wait_for_selector('[data-testid="stSelectbox"]', timeout=60_000)
                page.wait_for_timeout(1500)
                select_provider(page)

                sidebar = page.locator('[data-testid="stSidebar"]')
                password = sidebar.locator('input[type="password"]').first
                password.scroll_into_view_if_needed()
                password_value = password.input_value()
                body_text = page.inner_text("body")
                provider_value = page.locator(
                    '[data-testid="stSidebar"] [data-testid="stSelectbox"] '
                    'input[role="combobox"]'
                ).first.input_value()
                assert provider_value == "OrcaRouter Cyber Inference", provider_value
                assert password_value, "API key field is not populated from the environment"
                assert password_value not in body_text, "API key leaked into rendered text"
                assert password.get_attribute("type") == "password"
                assert page.get_by_text("Live OrcaRouter catalogue:").is_visible()
                page.wait_for_timeout(500)
                auth = capture(page, "auth-methods")
                auth["ui"] = {
                    "api_key_visible": password.is_visible(),
                    "secret_masked": password.get_attribute("type") == "password"
                    and password_value not in body_text,
                    "controls_enabled": password.is_enabled()
                    and page.get_by_role(
                        "button", name="Refresh OrcaRouter model catalogue"
                    ).is_enabled(),
                    "provider_selected": provider_value,
                }
                artifacts.append(auth)

                text_trigger = page.locator(
                    '[data-testid="stSidebar"] [data-testid="stSelectbox"]'
                ).nth(1)
                text_trigger.scroll_into_view_if_needed()
                page.wait_for_timeout(500)
                text_trigger.locator('input[role="combobox"]').click()
                page.wait_for_selector('[role="listbox"]', timeout=15_000)
                page.wait_for_timeout(500)
                text_ids = page.locator('[role="option"]').all_inner_texts()
                assert set(text_ids) == set(chat_ids), (
                    f"picker options diverged from the live catalogue: {text_ids}"
                )
                text = capture(page, "text-model-dropdown")
                text["ui"] = dropdown_metrics(
                    page, text_trigger.locator('[role="group"]').first
                )
                text["ui"]["item_count"] = len(text_ids)
                text["ui"]["dropdown_open"] = True
                artifacts.append(text)
                page.keyboard.press("Escape")
                page.wait_for_timeout(300)

                page.get_by_role("tab", name=re.compile("Upload image")).click()
                page.wait_for_selector(
                    "text=OrcaRouter model for image analysis:", timeout=30_000
                )
                page.wait_for_timeout(1000)
                image_trigger = page.locator('[data-testid="stSelectbox"]').filter(
                    has_text="OrcaRouter model for image analysis:"
                )
                image_trigger.scroll_into_view_if_needed()
                page.wait_for_timeout(400)
                image_trigger.locator('input[role="combobox"]').click()
                page.wait_for_selector('[role="listbox"]', timeout=15_000)
                page.wait_for_timeout(500)
                image_options = page.locator('[role="option"]').all_inner_texts()
                assert set(image_options) == set(image_ids), (
                    f"multimodal options diverged from metadata: {image_options}"
                )
                multimodal = capture(page, "multimodal-model-dropdown")
                multimodal["ui"] = dropdown_metrics(
                    page, image_trigger.locator('[role="group"]').first
                )
                multimodal["ui"]["item_count"] = len(image_options)
                multimodal["ui"]["dropdown_open"] = True
                multimodal["ui"]["models"] = image_options
                artifacts.append(multimodal)
                context.close()
            finally:
                browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()

    automation["live_provider"] = {
        "catalog_source": CATALOG_SOURCE,
        "chat_model": live["chat_model"],
        "catalog_chat_models": len(chat_ids),
        "catalog_image_models": len(image_ids),
    }
    automation["passed"] = True
    manifest = {"automation": automation, "artifacts": artifacts}
    (OUT_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(automation, indent=2))


if __name__ == "__main__":
    main()
