# Base Sepolia sandbox meter (Track B2)

This is a deterministic cryptographic cheque meter, not an inference provider.
It verifies authenticated 167-byte Session MAC cheques and returns receipts or
one explicitly labeled SSE meter event. It does not answer prompts, execute
services, send transactions, or transfer USDC. The receipt's settled status and
metrics describe local in-memory accounting only. Gas is zero because there
is no on-chain submission. Do not send production funds or production keys.

## Local verification

Use a Python interpreter with the existing SDK dependencies available. The
server itself adds no dependencies beyond the standard library and the SDK.
The SDK also needs its existing native shared library or its Python crypto
fallback. From the repository root:

    python3 scripts/run_testnet_sandbox.py
    curl http://127.0.0.1:8402/health
    pytest -v tests/test_testnet_sandbox.py

The script also works by absolute path from another working directory. It
binds loopback by default. CLI options:

    --host 127.0.0.1
    --port 8402
    --delta-v 1.0
    --unit-price-micro 500
    --vault-address 0x901c98Da847DD24ff23FcC37B6D1549A17F12253
    --payout-address 0x0000000000000000000000000000000000000000

The payout address can instead be set with CSLS_SANDBOX_PAYOUT_ADDRESS.
The vault and payout addresses are advertised metadata, not transfer targets
used by this process. Verify them for your own testnet environment.

## Service installation

Provision an existing Linux host with systemd, Python, and the SDK's existing
dependencies. Place a read-only deployment copy of this repository at
/opt/causal-slash, including the native library if using the native backend.
The provided unit uses /usr/bin/python3; adjust the installed unit's ExecStart
to a dedicated interpreter if SDK dependencies live in a virtual environment.
Do not use a Python interpreter under a home directory: ProtectHome is enabled.
No application database or writable application directory is needed.

    sudo install -m 0644 /opt/causal-slash/deploy/csls-sandbox.service /etc/systemd/system/csls-sandbox.service
    sudo install -m 0600 /dev/null /etc/csls-sandbox.env
    sudoedit /etc/csls-sandbox.env

Optional environment file content (replace with your testnet payout address):

    CSLS_SANDBOX_PAYOUT_ADDRESS=0x0000000000000000000000000000000000000000

    sudo systemctl daemon-reload
    sudo systemctl enable --now csls-sandbox.service
    sudo systemctl status csls-sandbox.service
    sudo journalctl -u csls-sandbox.service -n 30 --no-pager
    curl http://127.0.0.1:8402/health

By default every process generates a fresh 32-byte vendor secret using the
OS-backed secrets module and logs only its compressed 33-byte public key,
plus the listening address. The --vendor-sk option accepts exactly 64 hex
characters with an optional 0x prefix; CSLS_SANDBOX_VENDOR_SK is its fallback.
Prefer a protected environment file to a command-line secret visible in process
arguments. Never print a vendor secret or put it in shell history or version
control. Malformed secrets cause a generic configuration error, not an echo
of the supplied value.

All sessions, anti-replay history, cumulative amounts, and metrics are volatile.
Keep the default fresh vendor identity after restart, then rediscover /health
and initialize new agent sessions. Reusing a fixed vendor identity across state
loss does not preserve replay protection. Do not treat this service as durable
or production settlement infrastructure. The exposure cap is not automatically
cleared; an agent exceeding --delta-v is rejected. A payout address is metadata
only and does not turn the meter into an on-chain settlement service.

## Public HTTPS endpoint

On an already provisioned HTTPS reverse-proxy host, point the DNS A/AAAA record
for sandbox.kadoclub.net to that host. Keep port 8402 private and expose only
the reverse proxy publicly. With an existing Caddy installation, add this site
to its operator-managed configuration:

    sandbox.kadoclub.net {
        request_body {
            max_size 64KB
        }
        reverse_proxy 127.0.0.1:8402 {
            flush_interval -1
        }
    }

Validate and reload the proxy using its installed service configuration. Allow
certificate issuance/renewal on the host's HTTP/HTTPS ports. Do not expose the
plain Python HTTP server directly to the Internet. Preserve X-Causal-Cheque,
Content-Type, and X-CSLS-Mode; do not cache responses or buffer SSE. Keep access
logs free of cheque headers and bodies. Configure public connection/rate limits
at the proxy: the meter intentionally retains session and cheque history in RAM.
The application independently caps bodies at 65536 bytes, rejects malformed
Content-Length with 400, and rejects unsupported transfer framing with 400.
The proxy must forward request bodies with Content-Length (dechunk if needed).

Alternatively, if an operator already has a managed tunnel, route its public
hostname sandbox.kadoclub.net to http://127.0.0.1:8402 with streaming enabled.
The application itself has no upstream credentials or external inference calls.

## Verify the public route

    curl https://sandbox.kadoclub.net/health
    CSLS_PUBLIC_RELAYS=https://sandbox.kadoclub.net csls

Check status=ok, network=base-sepolia, provider_id=csls-base-sepolia-sandbox,
matching vendor_pk/provider_pk, settlement_mode=session_mac_167b, and the unit
price of 500 micro-USDC. A successful terminal chat displays the explicit
[CSLS TESTNET SANDBOX] verification event, never an invented model response.

Session initialization accepts POST /v1/session/init or /v1/session with a raw
95-byte application/octet-stream body, or a JSON session_init_pkt/packet hex
field. Meter routes are /v1/sandbox/meter, /v1/chat/completions, and
/v1/service/execute. Each requires X-Causal-Cheque with exactly 167 decoded
bytes (optional 0x). Missing, invalid, replayed, out-of-order, or over-cap
cheques return 403. Equivocation returns 409 with code -20 and the actual
algebraically extracted offender key in the proof; that response is sensitive
and must not be logged by the proxy. Only chat with JSON stream=true emits SSE.

    curl -i -X POST https://sandbox.kadoclub.net/v1/sandbox/meter -H 'Content-Type: application/json' --data '{}'

This negative check must return 403, CHEQUE_REQUIRED, code -25, and
X-CSLS-Mode: testnet-sandbox-meter. Check /health metrics again after real
SDK-backed test traffic. Do not deploy if the vendor key, network, or mode
is unexpected.
