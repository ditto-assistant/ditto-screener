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

## Backward-compatible v6 rollout

This extraction does not bump policy, change signing bytes, migrate data, or
repin production by itself. Keep production on release `v0.4.2` / policy 6 while
the PRs are reviewed.

1. Merge `ditto-screener` first. Configure its repository/environment secrets
   and read-only deploy key. Keep `SCREENER_POLICY_MANIFEST_FILE` unset for the
   first deployment so the worker runs the behavior-identical v6 build/health
   core with the synthetic `/run` assertion disabled.
2. Deploy the new v6 worker alongside the old v6 worker. The platform's atomic,
   oldest-first lease claim and unique running-attempt constraint prevent a
   submission from being claimed twice. Verify policy preflight, `attempt_id`
   and deadline retention, signed pass, deterministic Rust-contract rejection,
   retryable `screening_failed`, and unchanged public history/statuses.
   Until the separate fleet-health platform PR lands, optional heartbeat 404s
   are throttled and do not gate claims or verdicts.
3. Merge and deploy `ditto-platform`. It consumes protocol package `0.6.1` from
   the exact reviewed screener commit but keeps policy 6 and the existing state
   machine. A mixed old/new worker fleet remains safe because both sign the
   identical v2 canonical message.
4. Stop the old subnet screener only after the extracted worker is healthy and
   draining leases. Let any already-claimed old-worker lease finish or expire;
   late/conflicting results remain rejected.
5. Merge and release `ditto-subnet` last to remove the obsolete runtime and
   deployment coupling. Miner submissions and validator behavior do not change.
6. Enable a protected private manifest only as a separate, reversible operator
   action. Timing/relay and random-control selectors may escalate to private
   challenges; they never terminally reject on their own.

At every step, late, expired, conflicting, wrong-policy, wrong-agent, and
wrong-signer verdicts remain rejected. Existing waiting-validator/evaluating
rows, prior score receipts, screening history, and active leases are untouched.

## Cache and disk maintenance

The scheduled deployment checks every five minutes. The updater performs
bounded BuildKit and dangling-image garbage collection at most once every six
hours, retaining 12 GB of recent build cache by default. Tunables are
`SCREENER_CACHE_GC_INTERVAL_SECONDS` and `SCREENER_CACHE_KEEP_STORAGE`.
Running containers and referenced images are never pruned.
