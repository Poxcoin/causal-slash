# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Network Discovery & Route Resolver for Causal-Slash M2M Clearing Protocol.
Resolves optimal live sovereign vendor nodes via public seed relays or configured endpoints.
"""

from __future__ import annotations
import httpx
from typing import Optional, Tuple, Dict, Any, List

DEFAULT_PUBLIC_RELAYS: List[str] = [
    "https://gateway.causal-slash.net",
    "https://relay.causal-slash.org",
]


class NetworkDiscovery:
    """Discovers and resolves live sovereign vendor nodes on the M2M network."""

    @staticmethod
    async def resolve_active_vendor(
        preferred_url: Optional[str] = None,
        timeout: float = 2.0,
    ) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """
        Discover an active vendor node.
        Tries preferred_url first, then falls back through public seed relays.
        Returns (vendor_url, health_data) or (None, None) if completely offline.
        """
        candidate_urls: List[str] = []
        if preferred_url:
            candidate_urls.append(preferred_url.rstrip("/"))
        for relay in DEFAULT_PUBLIC_RELAYS:
            r_clean = relay.rstrip("/")
            if r_clean not in candidate_urls:
                candidate_urls.append(r_clean)

        async with httpx.AsyncClient(timeout=timeout) as client:
            for url in candidate_urls:
                try:
                    resp = await client.get(f"{url}/health")
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("vendor_pk"):
                            return url, data
                except Exception:
                    continue

        return None, None
