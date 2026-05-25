# Streamlit Community Cloud entry shim.
# The real app lives at apps/web/main.py; this file exists only because the SCC
# app's "Main file path" cannot be changed without re-creating the app and
# losing its history/stats. Remove if SCC ever exposes that setting.

import runpy
import sys
from pathlib import Path

_APP_DIR = Path(__file__).resolve().parent / "apps" / "web"
sys.path.insert(0, str(_APP_DIR))
runpy.run_path(str(_APP_DIR / "main.py"), run_name="__main__")
