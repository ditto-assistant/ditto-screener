# Production deployment

Production runs as the `ditto-screener` systemd unit on the isolated
`ditto-screener-prod` VM. GitHub Actions authenticates to GCP with Workload
Identity Federation, copies the updater over IAP, and deploys the exact tested
commit. The updater keeps the old process running through fetch and dependency
sync, restarts only after the checkout is ready, verifies systemd plus an
authenticated read-only queue preflight, and rolls back if the new process does
not become healthy.

## Required GitHub secrets

Repository secrets:

- `GCP_WIF_PROVIDER`: full Workload Identity Provider resource name. It should
  trust only the `ditto-assistant/ditto-screener` repository and the production
  environment.
- `GCP_SCREENER_DEPLOY_SA`: email of a dedicated screener deploy service
  account. Grant only IAP tunnel access, instance lookup, and SSH access to
  `ditto-screener-prod`.
- `RELEASE_TOKEN`: fine-grained token or GitHub App token scoped only to this
  repository's contents, used to write semantic-release commits and tags when
  branch protection prevents `GITHUB_TOKEN` from doing so.

The production host additionally needs a read-only deploy key for this private
repository. Store its private half only in the deploy user's SSH configuration;
register the public half as `DITTO_SCREENER_REPO_DEPLOY_KEY` with read-only
access to `ditto-assistant/ditto-screener`.

Runtime secrets stay in `/opt/ditto/screener/screener.env` on the VM:

- `SCREENER_API_TOKEN`: bearer token shared with the platform API.
- `SCREENER_MNEMONIC`, or the protected wallet files selected by
  `SCREENER_WALLET_NAME` and `SCREENER_WALLET_HOTKEY`.
- The file referenced by `SCREENER_GH_TOKEN_FILE`, when private harness
  dependency access is required. Its token should have read-only contents
  access to only that dependency repository.

Never put any of these values in source, workflow arguments, logs, or PR text.

## Compatible rollout

1. Merge this repository first. Install the read-only deploy key on the VM and
   configure its three repository secrets. Let the extracted worker deploy
   while the platform still requires policy 6. The worker supports that
   conservative handoff mode and signs policy 6 exactly.
2. Merge and deploy the platform PR. It switches the required policy to 7 and
   consumes protocol package 0.7.0 from an exact commit in this repository. The
   extracted worker automatically begins claiming policy-7 leases. Any old
   policy-6 worker refuses the handshake before claim.
3. Confirm queue drain, a policy-7 signed pass and rejection, public attempt
   history, and validator ticket issuance. Then merge the subnet removal PR.
4. Remove the old platform-owned screener deploy workflow only as part of step
   2, after this repository's scheduled deployment is green.

The unique running-attempt index prevents old and new workers from claiming the
same submission during overlap. Attempt ID, agent ID, screener hotkey, verdict,
and policy version remain bound into the canonical signature. Late, expired,
wrong-policy, wrong-agent, and wrong-signer verdicts remain rejected by the
platform.

## Cache and disk maintenance

The scheduled deployment runs every five minutes. The updater performs bounded
Docker BuildKit and dangling-image garbage collection at most once every six
hours, retaining 12 GB of recent build cache by default. Tunables are
`SCREENER_CACHE_GC_INTERVAL_SECONDS` and `SCREENER_CACHE_KEEP_STORAGE`.
Running containers and referenced images are never pruned.
