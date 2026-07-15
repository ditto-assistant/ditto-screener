"""The screener's INFO logs survive bittensor's WARNING clamp."""

from __future__ import annotations

import logging

from ditto_screener.__main__ import _PACKAGE_ROOT, _apply_ditto_logging


def test_apply_ditto_logging_unclamps_the_screener_tree() -> None:
    # Per-module loggers exist before bittensor initialises (they are created by
    # the module-level ``getLogger(__name__)`` calls at import time)...
    worker_logger = logging.getLogger(f"{_PACKAGE_ROOT}.worker")
    gate_logger = logging.getLogger(f"{_PACKAGE_ROOT}.gate")
    # ...then bittensor's lazy init (during keypair load) clamps every existing
    # logger to WARNING, which would hide sweep and per-agent verdict lines.
    worker_logger.setLevel(logging.WARNING)
    gate_logger.setLevel(logging.WARNING)

    try:
        _apply_ditto_logging()

        assert worker_logger.isEnabledFor(logging.INFO)
        assert gate_logger.isEnabledFor(logging.INFO)
    finally:
        worker_logger.setLevel(logging.NOTSET)
        gate_logger.setLevel(logging.NOTSET)


def test_package_root_is_the_extracted_package_not_the_validator() -> None:
    # A bare ``ditto`` here would silently no-op against the ``ditto_screener.*``
    # tree that actually gets clamped.
    assert _PACKAGE_ROOT == "ditto_screener"
