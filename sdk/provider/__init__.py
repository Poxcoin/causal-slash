# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Causal-Slash Protocol: Independent Service Provider Module.
Provides an autonomous, non-custodial service provider daemon exposing
discoverable capabilities, C11 Session MAC verification, and direct L2 settlement.
"""

from .server import IndependentProvider, StandaloneProviderServer

__all__ = ["IndependentProvider", "StandaloneProviderServer"]
