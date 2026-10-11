# PyPI Release Checklist: causal-slash-sdk 0.3.0

Release date: 2026-10-03
Package: causal-slash-sdk
Version: 0.3.0 (verified in pyproject.toml line 7 and sdk/__init__.py line 132)
Artifacts (in dist/):
- causal_slash_sdk-0.3.0-py3-none-any.whl
- causal_slash_sdk-0.3.0.tar.gz

All commands below were executed in this session from the repository root
(the Causal_Slash_Protocol project directory).

## 1. Test gate (PASSED)

Command:

    python3 -m pytest test/ -q 2>&1 | tail -5

Output:

    ......................................................................   [100%]
    70 passed in 10.39s

## 2. Build (PASSED)

Toolchain: python3 -m build 1.6.1, setuptools>=61 backend.

Command:

    python3 -m build 2>&1 | tail -3

Output:

    !!
    Successfully built causal_slash_sdk-0.3.0.tar.gz and causal_slash_sdk-0.3.0-py3-none-any.whl

## 3. Distribution metadata check (PASSED)

Toolchain: twine 7.0.0.

Command:

    python3 -m twine check dist/* 2>&1 | tail -5

Output:

    Checking dist/causal_slash_sdk-0.3.0-py3-none-any.whl: PASSED
    Checking dist/causal_slash_sdk-0.3.0.tar.gz: PASSED

## 4. Wheel contents: native libs and py.typed (PASSED)

Command:

    unzip -l dist/causal_slash_sdk-0.3.0-py3-none-any.whl | grep -E "\.so|py\.typed"

Output:

        67584  2026-10-03 14:51   sdk/libbloodhound.so
        59088  2026-10-03 14:51   sdk/libcausal_slash.so
           26  2026-10-02 21:36   sdk/py.typed

Both native libraries and the py.typed marker are present inside the wheel.

## 5. Human-only publish step (DO NOT run in automation)

The publish/upload step must be performed by a human. It is NOT part of this
preparation task and was NOT executed.

Publish command (requires a PyPI account token configured, e.g. via
keyring or TWINE_USERNAME/TWINE_PASSWORD environment variables):

    python3 -m twine upload dist/*

## 6. Post-publish verification (human, after upload)

In a fresh terminal:

    python3 -m venv /tmp/cs-verify-venv
    source /tmp/cs-verify-venv/bin/activate
    pip install causal-slash-sdk==0.3.0

Then verify import and version:

    python3 -c "import sdk; print(sdk.__version__)"

Expected output:

    0.3.0

Then deactivate and clean up:

    deactivate
    rm -rf /tmp/cs-verify-venv

Also verify on the web UI: https://pypi.org/project/causal-slash-sdk/0.3.0/
