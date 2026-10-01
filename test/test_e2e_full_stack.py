# SPDX-License-Identifier: Apache-2.0
import os
import sys

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TEST_DIR)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "examples"))
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "sdk"))

import e2e_full_stack_live as e2e


def test_full_stack_e2e_all_stages():
    """
    Runs the complete E2E (streaming, Kirchhoff clearing, double-spend,
    Bloodhound, calldata). The C-level 35ns gate is skipped here because it
    compiles a sanitizer build; it is asserted by the example itself and by
    `make test-bloodhound`.
    """
    stats = e2e.run(with_c_gate=False)

    assert stats["total_cheques"] >= 1_700
    assert stats["total_streamed_micro"] > 160_000_000
    assert stats["compression_ratio"] >= 0.99, "netting compression below 99%"
    assert stats["cycles_resolved"] > 0
    assert stats["treasury_fee_micro"] > 0
    assert stats["treasury_income_micro"] == stats["treasury_fee_micro"]
    # Fraud chain closed end-to-end:
    assert len(stats["commit_hash"]) == 64
    assert len(stats["attacker_address"]) == 40
    # Honest FFI measurement exists (Python path; ~tens of microseconds).
    assert 0 < stats["ffi_ns_per_op"] < 100_000
    assert stats["peak_rss_mb"] < 1500
