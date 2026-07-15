from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_deploy_workflow_discovers_screeners_by_label_not_a_fixed_vm() -> None:
    workflow = (ROOT / ".github" / "workflows" / "deploy.yml").read_text()

    # The pet VM name/zone are no longer hardcoded: discovery is label-driven.
    assert "SCREENER_VM: ditto-screener-prod" not in workflow
    assert "GCP_ZONE: us-central1-c" not in workflow
    assert "labels.env=prod" in workflow
    assert "labels.role=screener" in workflow
    assert "labels.role=screener-fleet" in workflow
    # Zone projection is normalized to a bare name for --zone.
    assert "zone.basename()" in workflow


def test_deploy_workflow_fans_out_over_the_fleet_in_parallel() -> None:
    workflow = (ROOT / ".github" / "workflows" / "deploy.yml").read_text()

    # Discovery feeds a matrix so hosts deploy concurrently (bounded), instead of
    # a sequential loop that could exceed the job timeout on a growing fleet.
    assert "matrix: ${{ fromJson(needs.discover.outputs.matrix) }}" in workflow
    assert "fail-fast: false" in workflow
    assert "max-parallel:" in workflow
    # Each host still runs the same exact-commit updater.
    assert "SCREENER_EXPECTED_SHA=${{ github.sha }}" in workflow


def test_updater_enables_the_unit_so_it_survives_a_reboot() -> None:
    updater = (ROOT / "scripts" / "update-screener.sh").read_text()

    # First boot restarts the unit but a reboot then short-circuits on the
    # bootstrap marker; the unit must be ENABLED to come back.
    assert "ensure_enabled" in updater
    assert 'systemctl enable "$SCREENER_UNIT"' in updater


def test_updater_reports_running_sha_from_a_marker_not_git_head() -> None:
    updater = (ROOT / "scripts" / "update-screener.sh").read_text()

    # The fast path must gate on the health-verified deployed-SHA marker, which
    # is written only AFTER a healthy restart — never on bare git HEAD, which a
    # run interrupted between reset and restart leaves at a not-yet-running SHA.
    assert "deployed_marker=" in updater
    assert "record_deployed_sha" in updater
    marker_write = updater.index('record_deployed_sha "$actual_sha"')
    health_check = updater.index("if ! wait_for_health")
    assert health_check < marker_write


def test_updater_and_bootstrap_serialize_on_a_shared_deploy_lock() -> None:
    updater = (ROOT / "scripts" / "update-screener.sh").read_text()
    bootstrap = (ROOT / "scripts" / "bootstrap-screener.sh").read_text()

    assert "flock" in updater
    assert "flock" in bootstrap
    # Bootstrap holds the lock and tells the updater it already holds it so the
    # nested updater invocation does not deadlock re-acquiring.
    assert "SCREENER_DEPLOY_LOCK_HELD=1" in bootstrap
    assert "SCREENER_DEPLOY_LOCK_HELD:-" in updater


def test_bootstrap_blocks_metadata_and_mounts_no_build_credential() -> None:
    bootstrap = (ROOT / "scripts" / "bootstrap-screener.sh").read_text()
    gate = (ROOT / "ditto_screener" / "gate.py").read_text()

    # IMDS guard: metadata IP dropped from Docker's FORWARD (DOCKER-USER) path.
    assert "169.254.169.254" in bootstrap
    assert "DOCKER-USER" in bootstrap
    # The reusable GH token is no longer fetched or handed to untrusted builds.
    # (The retryable-error deny-list markers for "secret gh_token" stay; it is
    # the BuildKit --secret MOUNT that must be gone from the build args.)
    assert "SCREENER_GH_TOKEN_SECRET" not in bootstrap
    assert "id=gh_token,src=" not in gate
    assert "--secret" not in gate


def test_bootstrap_bake_mode_provisions_before_any_secret() -> None:
    bootstrap = (ROOT / "scripts" / "bootstrap-screener.sh").read_text()

    assert "SCREENER_BAKE_ONLY" in bootstrap
    # Bake must exit before fetching any secret, so nothing sensitive is baked.
    bake_exit = bootstrap.index(
        'if [[ "$SCREENER_BAKE_ONLY" == "1" ]]; then\n  runuser'
    )
    first_secret = bootstrap.index('read_secret "$SCREENER_MNEMONIC_SECRET"')
    assert bake_exit < first_secret
    # The deploy key is installed only outside bake mode (never baked in).
    assert (
        'if [[ "$SCREENER_BAKE_ONLY" != "1" ]]; then\n  install -o "$SCREENER_USER"'
        in bootstrap
    )


def test_golden_image_bake_pipeline_exists() -> None:
    packer = (ROOT / "packer" / "screener-fleet.pkr.hcl").read_text()
    workflow = (ROOT / ".github" / "workflows" / "bake-image.yml").read_text()

    assert "image_family      = var.image_family" in packer
    assert "ditto-screener-fleet" in packer
    # Bakes via the same bootstrap script in bake mode; stores no secret.
    assert "SCREENER_BAKE_ONLY=1" in packer
    assert "environment: prod" in workflow
    assert "GCP_SCREENER_BAKE_SA" in workflow


def test_systemd_unit_runs_the_extracted_screener_entrypoint() -> None:
    unit = (ROOT / "deploy" / "ditto-screener.service").read_text()

    assert "ExecStart=/opt/ditto/screener/src/.venv/bin/ditto-screener" in unit
    assert "ditto.screener" not in unit
    assert "KillMode=mixed" in unit
    assert "TimeoutStopSec=35min" in unit


def test_updater_installs_and_rolls_back_the_repository_owned_unit() -> None:
    updater = (ROOT / "scripts" / "update-screener.sh").read_text()

    assert 'unit_source="$checkout/deploy/ditto-screener.service"' in updater
    assert 'install -o root -g root -m 0644 "$unit_source" "$unit_file"' in updater
    assert 'install -o root -g root -m 0644 "$unit_backup" "$unit_file"' in updater
    assert "consecutive_healthy" in updater
    assert "validator-openrouter-key" in updater
    assert "ditto-app-dev" in updater
    assert 'install -o "$SCREENER_USER" -g ditto -m 0400' in updater
    assert "SCREENER_SOURCE_REVIEW_API_KEY_FILE" in updater
    assert "required_policy_version" in updater
    assert "SCREENING_POLICY_VERSION" in updater


def test_updater_drops_the_stale_pre_extraction_namespace() -> None:
    updater = (ROOT / "scripts" / "update-screener.sh").read_text()

    # git reset --hard leaves the untracked ``ditto/`` namespace behind, which
    # keeps shadowing the ``ditto_screener`` import path.
    assert 'git -C "$checkout" clean -fd -- ditto' in updater


def test_updater_defers_daemon_restart_during_an_active_build() -> None:
    updater = (ROOT / "scripts" / "update-screener.sh").read_text()

    assert "build_in_flight" in updater
    assert 'pgrep -f "build -t ditto-screen"' in updater
    # The guard must sit before the disruptive docker restart.
    guard = updater.index("deferring daemon.json apply")
    restart = updater.index("systemctl restart docker")
    assert guard < restart
