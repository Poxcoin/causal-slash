"""Eight live-HTTP integration tests using real SDK cryptography, not mocks."""

from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

import pytest

from scripts.run_testnet_sandbox import (
    DEFAULT_VAULT, METER_PATHS, SandboxState, create_sandbox_server,
)
from sdk.causal_slash import (
    CausalAgentWallet, CSLS_ERR_BAD_MAC, CSLS_ERR_EXPOSURE_CAP,
    CSLS_ERR_FORGED_HASH, CSLS_ERR_NO_SESSION, CSLS_ERR_OUT_OF_ORDER,
    CSLS_ERR_REPLAY, derive_public_key, ecdh_x, mac128, pack_cheque,
    session_kdf, sign_cheque_python, unpack_session_init,
)

ROOT = Path(__file__).resolve().parents[1]
VENDOR_SK = (17).to_bytes(32, "big")


@pytest.fixture
def sandbox(monkeypatch):
    monkeypatch.delenv("CSLS_SANDBOX_VENDOR_SK", raising=False)
    monkeypatch.delenv("CSLS_SANDBOX_PAYOUT_ADDRESS", raising=False)
    server = create_sandbox_server(port=0, vendor_sk=VENDOR_SK)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=10)
        server.server_close()
        assert not thread.is_alive()


def request(server, method, path, body=b"", headers=None):
    connection = http.client.HTTPConnection(*server.server_address, timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        raw = response.read()
        data = (json.loads(raw) if response.getheader("Content-Type") == "application/json"
                else raw.decode("utf-8"))
        return response.status, dict(response.getheaders()), data
    finally:
        connection.close()


def initialize(server, wallet):
    packet = wallet.create_session(server.state.vendor_pk)
    status, _, result = request(server, "POST", "/v1/session/init", packet,
                                {"Content-Type": "application/octet-stream"})
    assert status == 200 and result["session_initialized"] is True
    nonce = unpack_session_init(packet)["session_nonce"]
    key = session_kdf(ecdh_x(wallet._sk_bytes, server.state.vendor_pk), nonce)
    return key


def crafted(wallet, vendor_pk, key, height, cumulative, forged=False):
    challenge, signature = sign_cheque_python(
        wallet._sk_bytes, wallet.public_key, vendor_pk, height, cumulative,
    )
    if forged:
        challenge = bytes([challenge[0] ^ 1]) + challenge[1:]
    raw = pack_cheque(wallet.public_key, vendor_pk, height, cumulative, challenge, signature)
    return raw + mac128(key[:16], raw)


def meter(server, cheque, path="/v1/sandbox/meter", body=b"{}"):
    return request(server, "POST", path, body,
                   {"X-Causal-Cheque": "0x" + cheque.hex(), "Content-Type": "application/json"})


def test_health_and_cli(sandbox, tmp_path, monkeypatch):
    status, _, health = request(sandbox, "GET", "/health")
    assert status == 200
    assert health == {
        "status": "ok", "vendor_pk": derive_public_key(VENDOR_SK).hex(),
        "provider_pk": derive_public_key(VENDOR_SK).hex(),
        "provider_id": "csls-base-sepolia-sandbox",
        "payout_address": "0x" + "0" * 40, "vault_address": DEFAULT_VAULT,
        "network": "base-sepolia", "unit_price_usdc": 0.0005,
        "unit_price_micro_usdc": 500, "settlement_mode": "session_mac_167b",
        "capabilities": ["session_mac_167b", "sandbox_meter", "equivocation_eots"],
        "metrics": dict(sessions_initialized=0, cheques_accepted=0, cheques_rejected=0,
                        equivocations_caught=0, total_settled_micro_usdc=0),
    }
    assert len(bytes.fromhex(health["vendor_pk"])) == 33
    script = str(ROOT / "scripts/run_testnet_sandbox.py")
    help_result = subprocess.run([sys.executable, script, "--help"], cwd=tmp_path,
                                 capture_output=True, text=True, timeout=15)
    assert help_result.returncode == 0
    for flag in ("--host", "--port", "--vendor-sk", "--delta-v", "--unit-price-micro",
                 "--vault-address", "--payout-address"):
        assert flag in help_result.stdout
    env = dict(os.environ, CSLS_SANDBOX_VENDOR_SK="0x" + VENDOR_SK.hex(),
               CSLS_SANDBOX_PAYOUT_ADDRESS="0x" + "1" * 40)
    process = subprocess.Popen([sys.executable, script, "--port", "0"], cwd=tmp_path,
                               env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output = ""
    try:
        output += process.stderr.readline()
        output += process.stderr.readline()
        port = int(output.split("sandbox listening on 127.0.0.1:")[1].splitlines()[0])
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            assert response.status == 200
            assert json.loads(response.read())["payout_address"] == "0x" + "1" * 40
        finally:
            connection.close()
    finally:
        process.terminate()
        stdout, stderr = process.communicate(timeout=10)
        output += stdout + stderr
    assert process.returncode == 0
    assert VENDOR_SK.hex() not in output
    assert "vendor_pk=" + health["vendor_pk"] in output
    bad_key = "z" * 64
    invalid = subprocess.run([sys.executable, script, "--vendor-sk", bad_key], cwd=tmp_path,
                             capture_output=True, text=True, timeout=15)
    assert invalid.returncode != 0 and bad_key not in invalid.stdout + invalid.stderr
    monkeypatch.delenv("CSLS_SANDBOX_VENDOR_SK", raising=False)
    state = SandboxState()
    try:
        assert len(state.vendor_pk) == 33
    finally:
        state.vendor.close()
    for key in ("0" * 64, "ff" * 32, "00", " " * 64):
        with pytest.raises(ValueError):
            SandboxState(vendor_sk=key)
    for delta in (0, -1, float("nan"), float("inf")):
        with pytest.raises(ValueError):
            SandboxState(delta_v=delta)
    assert request(sandbox, "GET", "/missing")[0] == 404


def test_session_aliases_binary_json_and_auth(sandbox):
    count = 0
    with CausalAgentWallet() as wallet:
        for path in ("/v1/session/init", "/v1/session"):
            for encoding in ("binary", "untyped", "session_init_pkt", "packet"):
                packet = wallet.create_session(sandbox.state.vendor_pk)
                if encoding in ("binary", "untyped"):
                    body = packet
                    headers = {"Content-Type": "application/octet-stream"} if encoding == "binary" else {}
                else:
                    body = json.dumps({encoding: "0x" + packet.hex()}).encode()
                    headers = {"Content-Type": "application/json"}
                status, _, data = request(sandbox, "POST", path, body, headers)
                assert status == 200
                assert data == {"ok": True, "session_initialized": True,
                                "vendor_pk": sandbox.state.vendor_pk_hex}
                count += 1
        packet = wallet.create_session(sandbox.state.vendor_pk)
        bad_auth = packet[:-1] + bytes([packet[-1] ^ 1])
        assert request(sandbox, "POST", "/v1/session", bad_auth)[0] == 403
        for body in (b"garbage", b"[]", b'{}', b'{"packet":"zz"}',
                     b'{"packet":null}', b"x" * 95, packet[:-1]):
            assert request(sandbox, "POST", "/v1/session", body)[0] == 400
    assert sandbox.state.health()["metrics"]["sessions_initialized"] == count


@pytest.mark.parametrize("path,error", [
    ("/v1/session/init", "INVALID_SESSION_PACKET"),
    ("/v1/sandbox/meter", "INVALID_JSON"),
])
def test_deeply_nested_json_returns_400_and_server_stays_healthy(sandbox, path, error):
    body = b"[" * 30000 + b"0" + b"]" * 30000
    assert len(body) == 60001 < 65536
    with CausalAgentWallet() as wallet:
        initialize(sandbox, wallet)
        cheque = wallet.sign_cheque(sandbox.state.vendor_pk, 0.0005, session_mac=True)
        status, headers, data = request(sandbox, "POST", path, body, {
            "Content-Type": "application/json",
            "X-Causal-Cheque": "0x" + cheque.raw_packet.hex(),
        })
        assert status == 400
        assert headers["Content-Type"] == "application/json"
        assert data == {"ok": False, "error": error}
        status, _, health = request(sandbox, "GET", "/health")
        assert status == 200 and isinstance(health, dict) and health["status"] == "ok"
        initialize(sandbox, wallet)
        cheque = wallet.sign_cheque(sandbox.state.vendor_pk, 0.0005, session_mac=True)
        assert meter(sandbox, cheque.raw_packet)[0] == 200


def test_missing_and_malformed_cheques(sandbox):
    rejected = 0
    for path in sorted(METER_PATHS):
        status, headers, data = request(sandbox, "POST", path, b"{}")
        assert status == 403
        assert headers["X-CSLS-Mode"] == "testnet-sandbox-meter"
        assert data == {"ok": False, "error": "CHEQUE_REQUIRED", "code": -25}
        rejected += 1
        for value in ("", "zz" * 167, "00" * 166, "00" * 168, "00" * 151,
                      "00 " * 167, "0x" + "0" * 333):
            status, headers, data = request(sandbox, "POST", path, b"{}", {"X-Causal-Cheque": value})
            assert status == 403
            assert headers["X-CSLS-Mode"] == "testnet-sandbox-meter"
            assert data == {"ok": False, "error": "INVALID_CHEQUE_FORMAT", "code": -1}
            rejected += 1
    assert sandbox.state.health()["metrics"]["cheques_rejected"] == rejected


def test_receipts_deltas_multiagent_and_concurrency(sandbox):
    def pay(index):
        with CausalAgentWallet(secret_key=(100 + index).to_bytes(32, "big")) as wallet:
            initialize(sandbox, wallet)
            receipts = []
            for path, micro in zip(sorted(METER_PATHS), (501, 999, 1501)):
                cheque = wallet.sign_cheque(sandbox.state.vendor_pk, micro / 1e6, session_mac=True)
                status, headers, receipt = meter(sandbox, cheque.raw_packet, path)
                assert status == 200
                assert headers["X-CSLS-Mode"] == "testnet-sandbox-meter"
                assert receipt == {
                    "ok": True, "status": "settled", "mode": "testnet_sandbox_meter",
                    "height": cheque.height, "cumulative_micro_usdc": sum((501, 999, 1501)[:len(receipts) + 1]),
                    "delta_micro_usdc": micro, "vendor_pk": sandbox.state.vendor_pk_hex,
                    "gas_wei": "0", "network": "base-sepolia",
                    "message": "[CSLS TESTNET SANDBOX] Verified 167B Session MAC cheque (no LLM inference executed)",
                }
                receipts.append(receipt)
            return receipts
    with ThreadPoolExecutor(max_workers=8) as executor:
        receipts = list(executor.map(pay, range(8)))
    assert len(receipts) == 8
    metrics = request(sandbox, "GET", "/health")[2]["metrics"]
    assert metrics == dict(sessions_initialized=8, cheques_accepted=24, cheques_rejected=0,
                           equivocations_caught=0, total_settled_micro_usdc=24008)
    with CausalAgentWallet() as wallet:
        initialize(sandbox, wallet)
        cheque = wallet.sign_cheque(sandbox.state.vendor_pk, 0.0005, session_mac=True).raw_packet
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: meter(sandbox, cheque), range(8)))
        assert sorted(result[0] for result in results) == [200] + [403] * 7
    metrics = sandbox.state.health()["metrics"]
    assert metrics["cheques_accepted"] == 25
    assert metrics["cheques_rejected"] == 7
    assert metrics["total_settled_micro_usdc"] == 24508


def test_replay_order_cap_and_auth_fail_closed(sandbox):
    with CausalAgentWallet() as wallet:
        key = initialize(sandbox, wallet)
        pk = sandbox.state.vendor_pk
        first = crafted(wallet, pk, key, 10, 500)
        assert meter(sandbox, first)[0] == 200
        attacks = [
            (first, CSLS_ERR_REPLAY),
            (crafted(wallet, pk, key, 9, 1000), CSLS_ERR_OUT_OF_ORDER),
            (crafted(wallet, pk, key, 11, 1000001), CSLS_ERR_EXPOSURE_CAP),
            (crafted(wallet, pk, key, 11, 1000, forged=True), CSLS_ERR_FORGED_HASH),
            (first[:-1] + bytes([first[-1] ^ 1]), CSLS_ERR_BAD_MAC),
        ]
        for raw, code in attacks:
            status, headers, data = meter(sandbox, raw)
            assert status == 403 and data["code"] == code
            assert headers["X-CSLS-Mode"] == "testnet-sandbox-meter"
        valid = crafted(wallet, pk, key, 11, 1000)
        assert meter(sandbox, valid, body=b"not-json")[0] == 400
        status, _, receipt = meter(sandbox, valid)
        assert status == 200 and receipt["delta_micro_usdc"] == 500
    with CausalAgentWallet() as outsider:
        outsider.create_session(pk)
        raw = outsider.sign_cheque(pk, 0.0005, session_mac=True).raw_packet
        status, _, data = meter(sandbox, raw)
        assert status == 403 and data["code"] in (CSLS_ERR_NO_SESSION, CSLS_ERR_BAD_MAC)
    metrics = sandbox.state.health()["metrics"]
    assert metrics["cheques_rejected"] == 6
    assert metrics["cheques_accepted"] == 2
    assert metrics["total_settled_micro_usdc"] == 1000


def test_equivocation_extracts_real_offender_key(sandbox):
    secret = (42).to_bytes(32, "big")
    with CausalAgentWallet(secret_key=secret) as wallet:
        key = initialize(sandbox, wallet)
        first = crafted(wallet, sandbox.state.vendor_pk, key, 1, 500)
        fork = crafted(wallet, sandbox.state.vendor_pk, key, 1, 750)
        assert meter(sandbox, first)[0] == 200
        status, headers, proof = meter(sandbox, fork)
        assert status == 409
        assert headers["X-CSLS-Mode"] == "testnet-sandbox-meter"
        assert proof == {
            "ok": False, "error": "EQUIVOCATION_DETECTED", "code": -20,
            "fraud_proof": {"extracted_secret_key": secret.hex(),
                            "offender_pk": wallet.public_key.hex(), "height": 1},
        }
        assert derive_public_key(bytes.fromhex(proof["fraud_proof"]["extracted_secret_key"])) == wallet.public_key
    assert sandbox.state.health()["metrics"] == dict(
        sessions_initialized=1, cheques_accepted=1, cheques_rejected=1,
        equivocations_caught=1, total_settled_micro_usdc=500,
    )


def test_openai_sse_meter_only(sandbox):
    with CausalAgentWallet() as wallet:
        initialize(sandbox, wallet)
        cheque = wallet.sign_cheque(sandbox.state.vendor_pk, 0.0005, session_mac=True)
        status, headers, body = meter(sandbox, cheque.raw_packet, "/v1/chat/completions",
                                      b'{"stream":true,"messages":[{"role":"user","content":"Say hello"}]}')
        assert status == 200
        assert headers["Content-Type"] == "text/event-stream; charset=utf-8"
        assert headers["Cache-Control"] == "no-cache"
        assert headers["X-CSLS-Mode"] == "testnet-sandbox-meter"
        events = body.split("\n\n")
        assert events[1:] == ["data: [DONE]", ""]
        chunk = json.loads(events[0].removeprefix("data: "))
        assert chunk == {
            "id": "csls-sandbox", "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"content":
                "[CSLS TESTNET SANDBOX] Verified 167B Session MAC cheque "
                f"height={cheque.height} cumulative=$0.0005 USDC (gas=0, mode=testnet-sandbox-meter)"},
                "finish_reason": "stop"}],
        }
        for path, body in (("/v1/chat/completions", b'{"stream":false}'),
                           ("/v1/chat/completions", b'{"stream":1}'),
                           ("/v1/service/execute", b'{"stream":true}')):
            raw = wallet.sign_cheque(sandbox.state.vendor_pk, 0.0005, session_mac=True).raw_packet
            status, headers, receipt = meter(sandbox, raw, path, body)
            assert status == 200 and headers["Content-Type"] == "application/json"
            assert "no LLM inference executed" in receipt["message"]
    assert sandbox.state.health()["metrics"]["total_settled_micro_usdc"] == 2000


def test_body_limits_and_malformed_framing(sandbox):
    def raw_request(headers, body=b""):
        with socket.create_connection(sandbox.server_address, timeout=10) as sock:
            message = b"POST /v1/sandbox/meter HTTP/1.0\r\nHost: localhost\r\n" + headers + b"\r\n" + body
            sock.sendall(message)
            sock.shutdown(socket.SHUT_WR)
            response = http.client.HTTPResponse(sock)
            response.begin()
            result = response.status, json.loads(response.read())
            response.close()
            return result
    for length in (b"65537", b"1000000000"):
        status, data = raw_request(b"Content-Length: " + length + b"\r\n")
        assert status == 413 and data["error"] == "BODY_TOO_LARGE"
    assert raw_request(b"", b"x" * 65537)[0] == 413
    assert raw_request(b"", b"x" * 65536)[0] == 403
    assert raw_request(b"Content-Length: 65536\r\n", b"x" * 65536)[0] == 403
    for length in (b"banana", b"-1", b"1.5", b""):
        assert raw_request(b"Content-Length: " + length + b"\r\n")[0] == 400
    assert raw_request(b"Content-Length: 5\r\n", b"xx")[0] == 400
    assert raw_request(b"Content-Length: 0\r\nContent-Length: 1\r\n")[0] == 400
    assert raw_request(b"Transfer-Encoding: chunked\r\n", b"0\r\n\r\n")[0] == 400
    assert request(sandbox, "POST", "/unknown")[0] == 404
