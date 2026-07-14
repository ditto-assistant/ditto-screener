from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_systemd_unit_runs_the_extracted_screener_entrypoint() -> None:
    unit = (ROOT / "deploy" / "ditto-screener.service").read_text()

    assert "ExecStart=/opt/ditto/screener/src/.venv/bin/ditto-screener" in unit
    assert "ditto.screener" not in unit


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
