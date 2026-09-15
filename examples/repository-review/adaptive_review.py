"""Prepare or resume a review whose worker assignments are planned at runtime."""

import sys
from pathlib import Path

# The outer launcher verifies this application tree before invoking Python -I.
# Only this explicit application directory joins the isolated installed imports.
sys.path.insert(0, str(Path(__file__).resolve().parent))

if __name__ == "__main__":
    from adaptive.cli import main

    main()
