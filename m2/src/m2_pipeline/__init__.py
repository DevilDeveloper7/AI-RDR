"""AI-RDR M2 preprocessing and windowing."""

from .schema import NormalizedEvent
from .windowing import SlidingWindowConfig, WindowRecord, iter_run_windows, iter_windows

__all__ = [
    "NormalizedEvent",
    "SlidingWindowConfig",
    "WindowRecord",
    "iter_run_windows",
    "iter_windows",
]
