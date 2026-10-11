# PACKAGING - how libcausal_slash.so reaches a clean machine

## Decision: prebuilt bundled .so (verified), not build-on-install

`libcausal_slash.so` and `libbloodhound.so` ship inside the wheel via
`[tool.setuptools.package-data]` (pyproject.toml lines 44-45). Build-on-install
via the Makefile was rejected: it would require a C11 toolchain, OpenSSL dev
headers and make on every consumer host, inside `pip install`. Bundled
prebuilt binaries install with no compiler and were proven to load from a
clean venv outside this repository.

## Evidence (this session, 2026-10-03 UTC)

- Build: `timeout 300 python3 -m build` ->
  `Successfully built causal_slash_sdk-0.3.0.tar.gz and causal_slash_sdk-0.3.0-py3-none-any.whl`
- `python3 -m twine check dist/*` -> both `PASSED`
- Wheel contents: `unzip -l` shows `sdk/libcausal_slash.so` (59088 B),
  `sdk/libbloodhound.so` (67584 B), `sdk/py.typed` (26 B), `LICENSE`
- Fresh venv OUTSIDE the repo (`/tmp/csls_venv_a1`, cwd `/tmp`):
  `pip install dist/causal_slash_sdk-0.3.0-py3-none-any.whl` -> rc 0, then
  `import sdk` + `CausalAgentWallet(agent_private_key=...)` instantiation ->
  `SMOKE_OK /tmp/csls_venv_a1/lib/python3.12/site-packages/sdk/slash_proxy.py`

## pyproject.toml changes made by this gate

1. Added missing classifier `License :: OSI Approved :: Apache Software License`.
2. Added missing runtime dependency `ecdsa>=0.13`. The first clean-venv smoke
   FAILED with `ModuleNotFoundError: No module named 'ecdsa'`
   (sdk/onchain_settler.py line 28, `import ecdsa`); a full scan of sdk/
   top-level imports confirmed the third-party set is exactly
   `pydantic` + `ecdsa` (ecdsa 0.19.2 is what the suite is tested against).

## Known limitation (flagged, not blocking this gate)

The wheel tag is `py3-none-any` while the bundled .so files are
linux-x86_64 ELF binaries: the wheel installs everywhere but native cheque
signing/verification works on linux-x86_64 only. macOS/Windows support
requires platform-specific wheels (future packaging work; needs a build
matrix decision). Pure-Python code paths import fine on any OS.
