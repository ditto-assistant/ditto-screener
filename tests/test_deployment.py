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


def test_updater_ensures_the_metadata_guard_on_every_deploy() -> None:
    # The pet VM was hand-provisioned and never ran bootstrap, so the guard has
    # to be (re)installed by the updater — the one path that runs on both the pet
    # and every fleet instance — or the pet keeps running exposed to metadata
    # exfil. It must run before the fast-path early-exit so a no-op deploy still
    # protects the host.
    updater = (ROOT / "scripts" / "update-screener.sh").read_text()

    assert "169.254.169.254" in updater
    assert "DOCKER-USER" in updater
    assert "ensure_imds_guard" in updater

    guard_call = updater.index("\nensure_imds_guard\n")
    fast_path = updater.index('echo "healthy: $SCREENER_UNIT already at')
    assert guard_call < fast_path


def test_imds_guard_preserves_gce_dns_before_dropping_metadata() -> None:
    """The metadata IP is also the GCE VM's DNS resolver.

    A broad DOCKER-USER drop caused every clean build to lose DNS. Both the
    golden-image bootstrap and the pet/fleet updater must install the same
    ordered policy: DNS first, all other metadata-server traffic second.
    """
    for script_name in ("bootstrap-screener.sh", "update-screener.sh"):
        script = (ROOT / "scripts" / script_name).read_text()
        guard_start = script.index("iptables -N DOCKER-USER")
        guard_end = script.index("\nGUARD", guard_start)
        guard = script[guard_start:guard_end]

        udp_dns = guard.index(
            '-A "$guard_tmp" -p udp -d 169.254.169.254/32 --dport 53 -j ACCEPT'
        )
        tcp_dns = guard.index(
            '-A "$guard_tmp" -p tcp -d 169.254.169.254/32 --dport 53 -j ACCEPT'
        )
        metadata_drop = guard.index('-A "$guard_tmp" -d 169.254.169.254/32 -j DROP')

        assert udp_dns < metadata_drop
        assert tcp_dns < metadata_drop
        replacement_jump = guard.index('-I DOCKER-USER 1 -j "$guard_tmp"')
        old_jump_removal = guard.index("-D DOCKER-USER -j DITTO-IMDS-GUARD")
        assert metadata_drop < replacement_jump < old_jump_removal
        assert "-D DOCKER-USER -d 169.254.169.254/32 -j DROP" in guard
        assert '-E "$guard_tmp" DITTO-IMDS-GUARD' in guard


def test_updater_restarts_changed_imds_guard_unit() -> None:
    updater = (ROOT / "scripts" / "update-screener.sh").read_text()

    assert (
        """if [[ "$changed" -eq 1 ]]; then
    systemctl daemon-reload
    systemctl restart ditto-imds-guard.service
  else
    systemctl start ditto-imds-guard.service
  fi"""
        in updater
    )


def test_updater_probes_dns_through_a_fresh_container_after_guarding_imds() -> None:
    updater = (ROOT / "scripts" / "update-screener.sh").read_text()

    assert "probe_docker_dns" in updater
    assert "getent hosts github.com" in updater
    guard_call = updater.index("\nensure_imds_guard\n")
    probe_call = updater.index("\nprobe_docker_dns\n")
    fast_path = updater.index('echo "healthy: $SCREENER_UNIT already at')
    assert guard_call < probe_call < fast_path


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
