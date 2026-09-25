"""
Compatibility bridge for legacy batch pipeline feature-extraction imports.
Allows `from enrichment.enrichment_manager import EnrichmentManager` in run_pipeline / run_live_pipeline
to load the batch CSV enricher while keeping Phase 4 investigation enricher in `enrichment.manager`.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_FEAT_EXT_DIR = Path(__file__).parent.parent / "feature extraction"
_LEGACY_PATH = _FEAT_EXT_DIR / "enrichment" / "enrichment_manager.py"

if _LEGACY_PATH.exists():
    try:
        _spec = importlib.util.spec_from_file_location("legacy_feat_enrichment", str(_LEGACY_PATH))
        if _spec and _spec.loader:
            _mod = importlib.util.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)
            EnrichmentManager = getattr(_mod, "EnrichmentManager")
        else:
            from enrichment.manager import EnrichmentManager
    except Exception:
        from enrichment.manager import EnrichmentManager
else:
    from enrichment.manager import EnrichmentManager

__all__ = ["EnrichmentManager"]
