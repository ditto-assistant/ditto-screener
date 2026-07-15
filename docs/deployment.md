# Production deployment

Production runs as the `ditto-screener` systemd unit on the isolated
`ditto-screener-prod` VM. GitHub Actions authenticates to GCP with Workload
Identity Federation, copies the updater over IAP, and deploys the exact tested
commit. The updater keeps the old process running through fetch and dependency
sync, installs the repository-owned systemd unit, restarts only after the
checkout is ready, verifies three consecutive systemd plus authenticated
read-only policy preflight checks, and rolls back both the code and unit if the
new process is not healthy.

## Required GitHub secrets

Repository or `prod` environment secrets:

- `GCP_WIF_PROVIDER`: Workload Identity Provider resource name. Trust only this
  private repository and its `prod` environment.
- `GCP_SCREENER_DEPLOY_SA`: dedicated deploy service-account email. Grant only
  IAP tunnel, instance lookup, and SSH access to `ditto-screener-prod`.
- `RELEASE_TOKEN`: fine-grained token or GitHub App token scoped only to this
  repository's contents, used for semantic-release commits, tags, and releases.

The production host additionally needs a private half of a read-only deploy key
in the deploy user's SSH configuration. Register only its public half as the
read-only `DITTO_SCREENER_REPO_DEPLOY_KEY` deploy key on this repository.

Runtime secrets stay in `/opt/ditto/screener/screener.env` or protected files on
the VM:

- `SCREENER_API_TOKEN`: bearer token shared with the platform API.
- `SCREENER_MNEMONIC`, or protected wallet files selected by
  `SCREENER_WALLET_NAME` and `SCREENER_WALLET_HOTKEY`.
- The file referenced by `SCREENER_GH_TOKEN_FILE`, when needed. Its token gets
  read-only contents access to only the private dependency repository.
- `SCREENER_AUDIT_SEED`, when the private random-control module is enabled.
- The protected files referenced by `SCREENER_POLICY_MANIFEST_FILE`, private
  module `feed_path`/`pack_path` values, and `SCREENER_REVIEW_JOURNAL_FILE`.
- `SCREENER_SOURCE_REVIEW_API_KEY_FILE`: mode-0400 OpenRouter key file readable
  only by the screener service user. The default reviewer model is
  `openai/gpt-5.6-luna`; every request enforces ZDR and denies data collection.

Never place any secret value, private challenge, private risk rule, or raw
artifact evidence in source, workflow arguments, logs, or PR text.

## Policy v7 rollout

1. Merge and deploy the platform protocol pin first. Existing v6 workers stop
   claiming because the queue advertises required policy version 7. Existing
   submissions and accepted validator scores are preserved.
2. Deploy the v7 worker. The updater materializes `validator-openrouter-key`
   from Secret Manager into a mode-0400 file and verifies that the platform
   requires the installed worker policy before declaring deployment healthy.
3. Verify a baseline pass, a quarantine path, signed results, heartbeats, and
   cache maintenance. Let any old-worker lease finish or expire; late or
   conflicting results remain rejected.
4. A protected private manifest remains an optional, reversible operator
   override. Timing and random-control selectors never terminally reject.

At every step, late, expired, conflicting, wrong-policy, wrong-agent, and
wrong-signer verdicts remain rejected. Existing waiting-validator/evaluating
rows, prior score receipts, screening history, and active leases are untouched.

## Cache and disk maintenance

Disk is bounded by two cooperating layers:

1. **Docker daemon builder GC** (`deploy/daemon.json`, installed by the
   updater; Docker restarts only when the file changes): BuildKit enforces the
   12 GB cache budget continuously, per build, so a heavy screening burst (for
   example a policy-rescreen wave that rebuilds every submission in a day)
   cannot outrun the scheduled pass.
2. **Updater backstop**: every scheduled run (five minutes) performs bounded
   garbage collection at most once per hour — `docker builder prune
   --keep-storage` with NO age filter (an age filter exempts exactly the
   burst-created cache that overruns the budget), dangling-image pruning after
   a week, and in-place truncation of the service log above 64 MB. Tunables
   are `SCREENER_CACHE_GC_INTERVAL_SECONDS` and `SCREENER_CACHE_KEEP_STORAGE`.
Running containers and referenced images are never pruned.
