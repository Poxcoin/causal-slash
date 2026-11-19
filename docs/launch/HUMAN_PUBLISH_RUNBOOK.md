# Human publish runbook: one evening, ordered gates

All commands below are for a human operator to run manually. They are not
instructions for an AI to execute. No push, tag, release, deployment, registry
upload, secret configuration, or search-console submission was performed while
writing this runbook. Stop on a failed gate; do not compress audit work into an
evening. Allow roughly one evening for publishing already-reviewed artifacts.

Prerequisites: reviewed local commits in both repositories; clean working trees;
passing project CI; GitHub, Cloudflare, PyPI and npm publisher access; Python
build/twine tools; Node/npm; GitHub CLI; optional provisioned Linux VPS with the
SDK dependencies and HTTPS proxy. Complete logins and any interactive security
prompts personally. Do not paste credentials into chat, commands, or version
control. Commands assume Bash and run from the stated directories.

## 1. Push reviewed local commits, then release v0.3.0

Review diffs and commit deliberately before this step. Do not blindly stage the
whole worktree: concurrent integration changes and untracked deployment files
require owner review. These commands push existing commits only; no force push.

```bash
set -euo pipefail
cd '/home/minus/Рабочий стол/Causal_Slash_Protocol'
git status --short
test -z "$(git status --porcelain)"
test "$(git branch --show-current)" = main
git push origin main
test "$(git rev-parse HEAD)" = "$(git ls-remote origin refs/heads/main | cut -f1)"

cd '/home/minus/Рабочий стол/csls_site'
git status --short
test -z "$(git status --porcelain)"
test "$(git branch --show-current)" = main
git push origin main
test "$(git rev-parse HEAD)" = "$(git ls-remote origin refs/heads/main | cut -f1)"

cd '/home/minus/Рабочий стол/Causal_Slash_Protocol'
if git rev-parse --verify --quiet refs/tags/v0.3.0 >/dev/null; then
  printf '%s\n' 'STOP: local v0.3.0 already exists; inspect it, do not retag.'
  exit 1
fi
if test -n "$(git ls-remote origin refs/tags/v0.3.0)"; then
  printf '%s\n' 'STOP: remote v0.3.0 already exists; inspect it, do not overwrite.'
  exit 1
fi
git tag -a v0.3.0 -m 'CSLS v0.3.0: testnet developer release'
git push origin refs/tags/v0.3.0
gh release create v0.3.0 --repo Poxcoin/causal-slash --verify-tag --title 'CSLS v0.3.0' --notes 'Testnet developer release. Python SDK metadata: 0.3.0. Testnet sandbox is a cheque meter, not inference or production settlement. External smart-contract audit remains a pre-mainnet milestone.'
gh release view v0.3.0 --repo Poxcoin/causal-slash --json tagName,isDraft,url
```

The tag/release is for the protocol repository, not an invented site release.
If resuming after a partial success, inspect the exact existing tag and release;
do not rerun creation commands or move a published tag. This source release
alone does not claim that either package registry has accepted an upload.

## 2. Configure intake, deploy site, verify, request indexing

Run in the site repository. Choose exactly one intake route initially.
The webhook must be your controlled persistent receiver, acknowledging only
saved records with status 200, 201, or 204. Wrangler prompts for its secret URL;
this administrative secret is not a credential supplied to agent clients.

```bash
cd '/home/minus/Рабочий стол/csls_site'
npx wrangler whoami
npx wrangler secret put EARLY_ACCESS_WEBHOOK_URL
npx wrangler secret list
```

Alternative to the webhook commands: create a KV namespace and bind it as
`EARLY_ACCESS_KV`. Run this block instead, not both routes by accident:

```bash
cd '/home/minus/Рабочий стол/csls_site'
npx wrangler whoami
npx wrangler kv namespace create EARLY_ACCESS_KV
"${EDITOR:-nano}" wrangler.jsonc
```

In `wrangler.jsonc`, add the following top-level property alongside the existing
settings. Replace the ID with the actual namespace ID returned by Wrangler;
merge with existing bindings instead of overwriting the configuration:

```json
"kv_namespaces": [
  { "binding": "EARLY_ACCESS_KV", "id": "REPLACE_WITH_CREATED_NAMESPACE_ID" }
]
```

Then, for either route:

```bash
cd '/home/minus/Рабочий стол/csls_site'
npm run lint
npm run test:worker
npm run build
npx wrangler deploy
curl -sS https://kadoclub.net/api/health
curl -fsS https://kadoclub.net/api/health | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("ok") is True and d.get("intakeConfigured") is True, d; print("PASS: intakeConfigured: true")'
```

Health must show `intakeConfigured: true`. That checks the binding, not durable
application delivery. Submit one genuine, consented application using
https://kadoclub.net/; confirm a successful receipt with submissionId and read
back the same record from the chosen webhook storage or Cloudflare KV dashboard.
Do not fabricate a team to test conversion. Do not announce intake as working
until persistence is verified. Review and commit any nonsecret binding change
manually, then push the reviewed site commit so deployed configuration matches
version control. Do not record the webhook URL in that commit.

In Google Search Console, choose the verified kadoclub.net property, inspect
`https://kadoclub.net/`, run Test live URL, and select Request indexing. Submit
`https://kadoclub.net/sitemap.xml` in Sitemaps if needed. Request submission is
not proof that Google has reindexed the site; check URL Inspection later.

References: [Cloudflare secrets](https://developers.cloudflare.com/workers/configuration/secrets/)
and [KV setup](https://developers.cloudflare.com/kv/get-started/).

## 3. Publish causal-slash-sdk 0.3.0

Use a reviewed release checkout with built native artifacts available for the
package, a clean `dist/`, and verified PyPI publisher access. Do not upload old
artifacts through the wildcard. These guards stop if old artifacts are present;
archive them manually outside the checkout before continuing.

```bash
cd '/home/minus/Рабочий стол/Causal_Slash_Protocol'
python3 -c 'import pathlib,tomllib; p=tomllib.loads(pathlib.Path("pyproject.toml").read_text()); assert p["project"]["name"] == "causal-slash-sdk" and p["project"]["version"] == "0.3.0"; assert not list(pathlib.Path("dist").glob("*")), "Archive stale dist artifacts before publishing"'
python3 -m build && twine check dist/* && twine upload dist/*
python3 -c 'import json,urllib.request; d=json.load(urllib.request.urlopen("https://pypi.org/pypi/causal-slash-sdk/0.3.0/json")); assert d["info"]["version"] == "0.3.0" and d["urls"]; print(d["info"]["name"], d["info"]["version"]); print("\n".join(x["filename"] for x in d["urls"]))'
```

The metadata guard uses Python 3.11+ `tomllib`. Inspect wheel/sdist contents,
platform compatibility, and native libraries before the upload; registry
acceptance alone is not a clean-environment SDK smoke test. Honor the Linux
x86_64 support declared in the README. Stop if 0.3.0 already exists on PyPI;
never imply an existing release can be overwritten.

## 4. Publish both npm packages, restore shared symlinks

Both manifests currently declare package version `1.0.0`; the protocol release
`v0.3.0` and Python version do not silently change npm versions. Confirm the
intended package names, versions, registry, ownership, and unpublished status
before running. Do not overwrite an existing published version. Inspect the
pack contents and source test output. No lockfile should be created.

The temporary install must not mutate the repository's shared `node_modules`.
This block requires the existing `../../node_modules` symlink, unlinks it, installs
package-local dependencies, and restores the symlink on normal exit or error.
The cleanup removes only that package's temporary dependency directory.

```bash
cd '/home/minus/Рабочий стол/Causal_Slash_Protocol'
for package in agentkit-causal-slash elizaos-plugin-causal-slash; do
  (
    set -euo pipefail
    cd "integrations/$package"
    test -L node_modules
    test "$(readlink node_modules)" = '../../node_modules'
    npm whoami
    npm config get registry
    npm pkg get name version
    unlink node_modules
    restore_shared_modules() {
      if test -d node_modules && ! test -L node_modules; then
        rm -rf -- node_modules
      fi
      if ! test -e node_modules && ! test -L node_modules; then
        ln -s ../../node_modules node_modules
      fi
    }
    trap restore_shared_modules EXIT
    npm install --no-package-lock && npm run build && npm test && npm publish --access public
  )
done
for package in agentkit-causal-slash elizaos-plugin-causal-slash; do
  test "$(readlink "integrations/$package/node_modules")" = '../../node_modules'
done
npm view @causal-slash/agentkit-action-provider@1.0.0 name version dist.integrity
npm view @causal-slash/elizaos-plugin@1.0.0 name version dist.integrity
git status --short
```

Stop if install/build/tests fail. If interrupted by power loss or forced kill,
inspect each package directory and restore its original symlink manually before
resuming. Registry reads confirm exact versions, not downstream integration
success. Retain the published tarball integrity and smoke-test installs in a
separate disposable environment before announcing availability.

## 5. Optional VPS sandbox deployment; no mainnet deployment

Use [deploy/SANDBOX_DEPLOY.md](../../deploy/SANDBOX_DEPLOY.md) as the canonical
installation and proxy guide. A human provisions an existing Linux host and a
reviewed read-only checkout at `/opt/causal-slash`, installs Python/SDK dependencies
and any required native library, and confirms `/usr/bin/python3` can import the
SDK. Do not treat a source-only copy without dependencies as deployable.

Run these commands on that VPS after provisioning, not on the development host:

```bash
sudo install -m 0644 /opt/causal-slash/deploy/csls-sandbox.service /etc/systemd/system/csls-sandbox.service
sudo systemctl daemon-reload
sudo systemctl enable --now csls-sandbox.service
sudo systemctl status csls-sandbox.service --no-pager
sudo journalctl -u csls-sandbox.service -n 30 --no-pager
curl -fsS http://127.0.0.1:8402/health
```

Manually configure DNS and the HTTPS reverse proxy for
`https://sandbox.kadoclub.net` per the deployment guide. Keep 8402 private;
set request/rate limits, preserve cheque headers, avoid body/header logging,
and do not buffer SSE. Then verify from the operator workstation:

```bash
curl -fsS https://sandbox.kadoclub.net/health
curl -sS -i -X POST https://sandbox.kadoclub.net/v1/sandbox/meter -H 'Content-Type: application/json' --data '{}'
CSLS_PUBLIC_RELAYS=https://sandbox.kadoclub.net csls
```

Check network `base-sepolia`, expected provider/vendor key,
`settlement_mode=session_mac_167b`, and unauthenticated rejection `403` with
`CHEQUE_REQUIRED`. Use test keys/assets only. A terminal session should display
the labeled sandbox meter event, never an inference result. Sessions and replay
history are volatile; restart with a fresh vendor identity and rediscover it.
The service neither submits transactions nor transfers USDC.

`scripts/deploy_base_mainnet.js` stays deferred until a pilot merchant is
secured and the independent external smart-contract audit is completed with
remediation and human approval. No mainnet command belongs in this evening's
execution. Keep genuine deployment receipts separate from test meter receipts.
