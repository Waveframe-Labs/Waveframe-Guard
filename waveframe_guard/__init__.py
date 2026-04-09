"""
Waveframe Guard — Public API

This module exposes the primary SDK interface.

Users should only need to import from here:

    from waveframe_guard import WaveframeGuard
"""

from .client import WaveframeGuard

__all__ = ["WaveframeGuard"]