"""
A deliberately mocked asset inventory, tied explicitly to Week 1's sample
hosts. Every real SOC has some source of truth for "what is this asset,
who owns it, how sensitive is it" (a CMDB, an EDR console, an IAM system);
building an integration to a real one is out of scope for this project, but
the *shape* of that context -- and the fact that the agent needs it to
reason well -- is real and worth having from Week 4 onward rather than
bolting it on later.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ASSET_INVENTORY_PATH = REPO_ROOT / "data" / "asset_inventory.json"


def load_asset_inventory(path: Path = DEFAULT_ASSET_INVENTORY_PATH) -> dict:
    return json.loads(path.read_text())


def make_asset_lookup(inventory: dict) -> Callable[[str], dict]:
    """Returns a function suitable for direct use as the agent's
    get_asset_context tool dispatch target."""

    def _lookup(hostname: str) -> dict:
        entry = inventory.get(hostname)
        if entry is None:
            return {
                "found": False,
                "hostname": hostname,
                "note": "Not in the asset inventory (this mock dataset only covers the Week 1 sample hosts).",
            }
        return {"found": True, "hostname": hostname, **entry}

    return _lookup
