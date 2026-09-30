# SPDX-License-Identifier: Apache-2.0
"""
SlashBench: High-Frequency M2M Micro-Settlement Performance Profiler
Measures real microsecond latency distribution (p50, p95, p99, max) and throughput of CSLS core.
"""

import time
import os
import sys
import numpy as np

_BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_BENCH_DIR)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "sdk"))

from causal_slash import CausalAgentWallet, CausalVendorNode

def run_slashbench(num_cheques: int = 10000):
    print("======================================================================")
    print("SLASHBENCH: HIGH-FREQUENCY M2M PERFORMANCE PROFILER")
    print("======================================================================")

    agent_sk = bytes([0x11] * 32)
    vendor_sk = bytes([0x22] * 32)

    agent = CausalAgentWallet(agent_sk)
    vendor = CausalVendorNode(vendor_sk, delta_v_usdc=100.0)

    sign_latencies = []
    verify_latencies = []
    e2e_latencies = []

    print(f"Profiling {num_cheques} sequential micro-settlements on local core...")

    t_start = time.perf_counter()
    for _ in range(num_cheques):
        t0 = time.perf_counter()
        pkt = agent.sign_cheque(vendor.public_key, amount_usdc=0.0001)
        t1 = time.perf_counter()
        res = vendor.process_cheque(pkt)
        t2 = time.perf_counter()

        assert res.accepted

        sign_us = (t1 - t0) * 1e6
        verify_us = (t2 - t1) * 1e6
        e2e_us = (t2 - t0) * 1e6

        sign_latencies.append(sign_us)
        verify_latencies.append(verify_us)
        e2e_latencies.append(e2e_us)

    t_end = time.perf_counter()
    total_elapsed = t_end - t_start
    total_throughput = num_cheques / total_elapsed

    print("")
    print("1. CHEQUE SIGNING LATENCY (Agent):")
    print(f"   p50 (median):  {np.percentile(sign_latencies, 50):.2f} us")
    print(f"   p95:           {np.percentile(sign_latencies, 95):.2f} us")
    print(f"   p99:           {np.percentile(sign_latencies, 99):.2f} us")
    print(f"   min / max:     {np.min(sign_latencies):.2f} us / {np.max(sign_latencies):.2f} us")

    print("")
    print("2. CHEQUE VERIFICATION LATENCY (Vendor):")
    print(f"   p50 (median):  {np.percentile(verify_latencies, 50):.2f} us")
    print(f"   p95:           {np.percentile(verify_latencies, 95):.2f} us")
    print(f"   p99:           {np.percentile(verify_latencies, 99):.2f} us")
    print(f"   min / max:     {np.min(verify_latencies):.2f} us / {np.max(verify_latencies):.2f} us")

    print("")
    print("3. END-TO-END LATENCY & THROUGHPUT (Sign + Verify):")
    print(f"   p50 (median):  {np.percentile(e2e_latencies, 50):.2f} us")
    print(f"   p95:           {np.percentile(e2e_latencies, 95):.2f} us")
    print(f"   p99:           {np.percentile(e2e_latencies, 99):.2f} us")
    print(f"   Throughput:    {total_throughput:.0f} ops/sec")
    print("======================================================================")

if __name__ == "__main__":
    run_slashbench(10000)
