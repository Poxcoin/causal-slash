# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Structured Observability, Telemetry & Prometheus Metrics for Causal-Slash.

Provides real-time production telemetry:
- Lock-free / thread-safe latency percentile tracking (p50, p95, p99)
- High-frequency throughput metrics (cheques/sec)
- Circuit Breaker trip monitoring and quota violations
- In-memory Kirchhoff netting compression ratio & volume cleared
- Full export to JSON and Prometheus exposition format
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger("causal_slash.telemetry")


class CausalMetrics:
    """
    Production-grade in-memory metrics aggregator with JSON & Prometheus exporters.
    """

    def __init__(self, window_size: int = 1000):
        self._lock = threading.RLock()
        self.window_size = window_size

        # Latency samples (microseconds)
        self._sign_latencies: Deque[float] = deque(maxlen=window_size)
        self._verify_latencies: Deque[float] = deque(maxlen=window_size)
        self._e2e_latencies: Deque[float] = deque(maxlen=window_size)

        # Counters
        self.total_cheques_signed: int = 0
        self.total_cheques_verified: int = 0
        self.total_volume_settled_micro: int = 0
        self.circuit_breaker_trips: int = 0
        self.quota_exceeded_trips: int = 0
        self.equivocations_caught: int = 0
        self.mesh_cycles_eliminated: int = 0
        self.mesh_cleared_volume_micro: int = 0

        # Throughput tracking
        self._throughput_timestamps: Deque[float] = deque(maxlen=5000)
        self._start_time: float = time.time()

    def record_sign(self, latency_us: float, amount_micro: int = 0) -> None:
        """Records a cheque signing event and latency."""
        now = time.time()
        with self._lock:
            self._sign_latencies.append(latency_us)
            self._throughput_timestamps.append(now)
            self.total_cheques_signed += 1
            self.total_volume_settled_micro += amount_micro

    def record_verify(self, latency_us: float) -> None:
        """Records a cheque verification event and latency."""
        with self._lock:
            self._verify_latencies.append(latency_us)
            self.total_cheques_verified += 1

    def record_e2e(self, latency_us: float) -> None:
        """Records an end-to-end payment round-trip latency."""
        with self._lock:
            self._e2e_latencies.append(latency_us)

    def record_circuit_breaker_trip(self) -> None:
        """Records a spend rate limit exceeded event."""
        with self._lock:
            self.circuit_breaker_trips += 1
        logger.warning("Circuit breaker limit tripped! Total trips: %d", self.circuit_breaker_trips)

    def record_quota_trip(self) -> None:
        """Records a subagent quota violation event."""
        with self._lock:
            self.quota_exceeded_trips += 1
        logger.warning("Subagent quota limit tripped! Total trips: %d", self.quota_exceeded_trips)

    def record_equivocation(self) -> None:
        """Records an equivocation detection and private key recovery event."""
        with self._lock:
            self.equivocations_caught += 1
        logger.critical("Equivocation attack intercepted! Total caught: %d", self.equivocations_caught)

    def record_mesh_netting(self, cycles: int, cleared_micro: int) -> None:
        """Records Kirchhoff cycle annihilation statistics."""
        with self._lock:
            self.mesh_cycles_eliminated += cycles
            self.mesh_cleared_volume_micro += cleared_micro

    def get_throughput_ops_sec(self) -> float:
        """Calculates instantaneous throughput over the active sliding window."""
        with self._lock:
            if len(self._throughput_timestamps) < 2:
                return 0.0
            dt = self._throughput_timestamps[-1] - self._throughput_timestamps[0]
            if dt <= 0:
                return 0.0
            return len(self._throughput_timestamps) / dt

    @staticmethod
    def _calc_percentiles(samples: List[float]) -> Dict[str, float]:
        if not samples:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "min": 0.0, "max": 0.0}
        s = sorted(samples)
        n = len(s)
        return {
            "p50": round(s[int(n * 0.50)], 2),
            "p95": round(s[int(min(n - 1, n * 0.95))], 2),
            "p99": round(s[int(min(n - 1, n * 0.99))], 2),
            "min": round(s[0], 2),
            "max": round(s[-1], 2),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Returns structured dictionary of all protocol metrics."""
        with self._lock:
            sign_p = self._calc_percentiles(list(self._sign_latencies))
            verify_p = self._calc_percentiles(list(self._verify_latencies))
            e2e_p = self._calc_percentiles(list(self._e2e_latencies))
            throughput = self.get_throughput_ops_sec()
            uptime_sec = time.time() - self._start_time

            return {
                "uptime_seconds": round(uptime_sec, 2),
                "throughput_ops_sec": round(throughput, 2),
                "latency_us": {
                    "sign": sign_p,
                    "verify": verify_p,
                    "e2e": e2e_p,
                },
                "traffic": {
                    "total_cheques_signed": self.total_cheques_signed,
                    "total_cheques_verified": self.total_cheques_verified,
                    "total_volume_settled_usdc": round(self.total_volume_settled_micro / 1e6, 6),
                },
                "security": {
                    "circuit_breaker_trips": self.circuit_breaker_trips,
                    "quota_exceeded_trips": self.quota_exceeded_trips,
                    "equivocations_caught": self.equivocations_caught,
                },
                "clearing_mesh": {
                    "cycles_eliminated": self.mesh_cycles_eliminated,
                    "cleared_volume_usdc": round(self.mesh_cleared_volume_micro / 1e6, 6),
                }
            }

    def to_json(self, indent: int = 2) -> str:
        """Exports metrics as formatted JSON."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_prometheus(self) -> str:
        """Exports metrics in standard Prometheus exposition format."""
        data = self.to_dict()
        lines: List[str] = [
            "# HELP csls_throughput_ops_sec Instantaneous cheque throughput ops/sec",
            "# TYPE csls_throughput_ops_sec gauge",
            f"csls_throughput_ops_sec {data['throughput_ops_sec']}",
            "",
            "# HELP csls_cheques_signed_total Total signed micro-cheques",
            "# TYPE csls_cheques_signed_total counter",
            f"csls_cheques_signed_total {data['traffic']['total_cheques_signed']}",
            "",
            "# HELP csls_cheques_verified_total Total verified micro-cheques",
            "# TYPE csls_cheques_verified_total counter",
            f"csls_cheques_verified_total {data['traffic']['total_cheques_verified']}",
            "",
            "# HELP csls_volume_settled_usdc Total settled volume in USDC",
            "# TYPE csls_volume_settled_usdc counter",
            f"csls_volume_settled_usdc {data['traffic']['total_volume_settled_usdc']}",
            "",
            "# HELP csls_sign_latency_us Cheque signing latency percentiles in microseconds",
            "# TYPE csls_sign_latency_us gauge",
            f'csls_sign_latency_us{{quantile="0.5"}} {data["latency_us"]["sign"]["p50"]}',
            f'csls_sign_latency_us{{quantile="0.95"}} {data["latency_us"]["sign"]["p95"]}',
            f'csls_sign_latency_us{{quantile="0.99"}} {data["latency_us"]["sign"]["p99"]}',
            "",
            "# HELP csls_circuit_breaker_trips_total Circuit breaker spend rate limit triggers",
            "# TYPE csls_circuit_breaker_trips_total counter",
            f"csls_circuit_breaker_trips_total {data['security']['circuit_breaker_trips']}",
            "",
            "# HELP csls_mesh_cycles_eliminated_total Kirchhoff debt cycles annihilated in RAM",
            "# TYPE csls_mesh_cycles_eliminated_total counter",
            f"csls_mesh_cycles_eliminated_total {data['clearing_mesh']['cycles_eliminated']}",
            "",
            "# HELP csls_mesh_cleared_volume_usdc Annihilated gross debt volume in USDC",
            "# TYPE csls_mesh_cleared_volume_usdc counter",
            f"csls_mesh_cleared_volume_usdc {data['clearing_mesh']['cleared_volume_usdc']}",
        ]
        return "\n".join(lines) + "\n"


# Global singleton instance for easy observability across all SDK modules
_GLOBAL_METRICS = CausalMetrics()


def get_metrics() -> CausalMetrics:
    """Returns the global CausalMetrics instance."""
    return _GLOBAL_METRICS
