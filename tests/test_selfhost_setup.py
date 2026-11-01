"""Exercise public installation boundaries without reading or changing pilot state."""

import importlib.util
import json
import os
import stat
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("setup_selfhost", ROOT / "scripts/setup_selfhost.py")
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)


def options(*extra):
    return setup.parser().parse_args(["configure", "--non-interactive", *extra])


@pytest.mark.parametrize('abi', [-1, 1, 5])
def test_unsupported_local_kernel_stops_before_build_or_service_start(tmp_path, monkeypatch, capsys, abi):
    class Call:
        def __call__(self, *args):
            assert args == (444, None, 0, 1)
            return abi

    class Library:
        syscall = Call()

    monkeypatch.setattr(setup.sys, 'platform', 'linux')
    monkeypatch.setattr(setup.platform, 'machine', lambda: 'x86_64')
    for name in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'CONTAINER_HOST'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(setup.ctypes, 'CDLL', lambda *a, **kw: Library())
    monkeypatch.setattr(setup.subprocess, 'run', lambda *a, **kw: pytest.fail('must not build or start'))
    assert setup.main(['start', '--runtime-dir', str(tmp_path / 'state')]) == 1
    assert 'container cannot upgrade the NAS kernel' in capsys.readouterr().err


def test_remote_engine_is_not_judged_by_the_installer_kernel(monkeypatch):
    monkeypatch.setattr(setup.sys, 'platform', 'linux')
    monkeypatch.setenv('DOCKER_HOST', 'ssh://operator@docker-host.invalid')
    monkeypatch.setattr(setup.ctypes, 'CDLL', lambda *a, **kw: pytest.fail('remote kernel is checked inside container'))
    setup.check_host_isolation()


def test_first_start_needs_no_provider_credentials_and_does_not_mutate_pilot(tmp_path):
    state = tmp_path / "state"
    config = setup.prepare(ROOT, state, options())
    assert config["authorized_mailboxes"] == []
    assert config["history_days"] == 30
    assert config["public_url"] == "http://localhost:8025"
    assert (state / "secrets/jev-key").read_text() == ""
    assert json.loads((state / "secrets/google-oauth-client.json").read_text()) == {}
    key = (state / "secrets/token-encryption-key").read_bytes()
    cipher = Fernet(key)
    assert cipher.decrypt(cipher.encrypt(b"connection")) == b"connection"
    for directory in (state, state / "secrets"):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o444 for path in (state / "secrets").iterdir())
    assert stat.S_IMODE((state / "settings.json").stat().st_mode) == 0o600
    originals = {path.name: path.read_bytes() for path in (state / "secrets").iterdir()}
    original_environment = (state / "compose.env").read_bytes()
    setup.prepare(ROOT, state, options())
    assert originals == {path.name: path.read_bytes() for path in (state / "secrets").iterdir()}
    assert " after:" in (state / "compose.env").read_text()
    assert (state / "compose.env").read_bytes() == original_environment


def test_explicit_import_is_private_and_does_not_rotate_database_keys(tmp_path, capsys):
    state = tmp_path / "state"
    setup.prepare(ROOT, state, options())
    old_key = (state / "secrets/token-encryption-key").read_bytes()
    old_revision = next(line for line in (state / "compose.env").read_text().splitlines() if line.startswith("MAILSEC_SETUP_REVISION="))
    key_file = tmp_path / "input-key"
    key_file.write_text("synthetic-api-key")
    oauth = tmp_path / "oauth.json"
    oauth.write_text(json.dumps({"web": {"client_id": "synthetic-client", "client_secret": "synthetic-secret",
                                        "redirect_uris": ["http://localhost:8125/oauth/google/callback"]}}))
    config = setup.prepare(ROOT, state, options("--port", "8125", "--history-days", "0", "--jev-key-file", str(key_file),
                                               "--oauth-client-file", str(oauth), "--mailboxes", "Person@gmail.com,Person@gmail.com"))
    assert config["authorized_mailboxes"] == ["person@gmail.com"]
    assert (state / "secrets/jev-key").read_text() == "synthetic-api-key"
    assert (state / "secrets/token-encryption-key").read_bytes() == old_key
    assert "newer_than:" not in (state / "compose.env").read_text()
    assert " after:" not in (state / "compose.env").read_text()
    assert "synthetic" not in (state / "compose.env").read_text()
    assert "synthetic" not in (state / "settings.json").read_text()
    new_revision = next(line for line in (state / "compose.env").read_text().splitlines() if line.startswith("MAILSEC_SETUP_REVISION="))
    assert new_revision != old_revision
    assert capsys.readouterr().out == ""
    before = (state / "secrets/google-oauth-client.json").read_bytes()
    setup.prepare(ROOT, state, options())
    assert before == (state / "secrets/google-oauth-client.json").read_bytes()


@pytest.mark.parametrize("extra", [
    ["--public-url", "http://192.0.2.1:8025"],
    ["--public-url", "https://user:secret@example.com"],
    ["--public-url", "https://example.com/path"],
    ["--public-url", "http://localhost:9000"],
    ["--mailboxes", "not-an-address"],
    ["--history-days", "-1"],
    ["--port", "80"],
    ["--trusted-proxy-ips", "*"],
    ["--trusted-proxy-ips", "127.0.0.1,*"],
    ["--trusted-proxy-ips", "0.0.0.0/0"],
    ["--trusted-proxy-ips", "::/0"],
    ["--trusted-proxy-ips", "proxy.invalid"],
    ["--project-name", "mailsec-pilot"],
])
def test_unsafe_or_invalid_configuration_rejected(tmp_path, extra):
    with pytest.raises(ValueError):
        setup.prepare(ROOT, tmp_path / "state", options(*extra))


def test_oauth_redirect_must_match_before_credentials_change(tmp_path):
    state = tmp_path / "state"
    setup.prepare(ROOT, state, options())
    client = tmp_path / "client.json"
    client.write_text(json.dumps({"web": {"client_id": "fake", "client_secret": "fake", "redirect_uris": []}}))
    with pytest.raises(ValueError, match="exact callback"):
        setup.prepare(ROOT, state, options("--oauth-client-file", str(client)))
    assert json.loads((state / "secrets/google-oauth-client.json").read_text()) == {}


def test_existing_foreign_directory_and_secret_symlinks_are_rejected(tmp_path):
    foreign = tmp_path / "pilot"
    foreign.mkdir()
    (foreign / "valuable").write_text("unchanged")
    with pytest.raises(ValueError, match="existing Mailsec"):
        setup.prepare(ROOT, foreign, options())
    assert (foreign / "valuable").read_text() == "unchanged"
    state = tmp_path / "state"
    setup.prepare(ROOT, state, options())
    secret = state / "secrets/jev-key"
    secret.unlink()
    secret.symlink_to(foreign / "valuable")
    key_file = tmp_path / "input-key"
    key_file.write_text("new-key")
    with pytest.raises(ValueError, match="symbolic link"):
        setup.prepare(ROOT, state, options("--jev-key-file", str(key_file)))
    assert (foreign / "valuable").read_text() == "unchanged"


def test_project_cannot_silently_switch_database(tmp_path):
    state = tmp_path / "state"
    setup.prepare(ROOT, state, options("--project-name", "mailsec-selfhost-family"))
    assert setup.prepare(ROOT, state, options())["project_name"] == "mailsec-selfhost-family"
    with pytest.raises(ValueError, match="different database"):
        setup.prepare(ROOT, state, options("--project-name", "mailsec-selfhost-other"))


def test_backup_pairs_dump_with_original_encryption_key_and_excludes_caches(tmp_path, monkeypatch):
    state = tmp_path / "state"
    setup.prepare(ROOT, state, options())

    def dump(command, **kwargs):
        assert command[-1] == "/opt/mailsec/container_backup.py"
        assert "mailsec" in command
        kwargs["stdout"].write(b"PGDMP-synthetic-test")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(setup.subprocess, "run", dump)
    previous = os.umask(0o077)
    try:
        archive = setup.backup(state, ["docker", "compose"], {})
    finally:
        os.umask(previous)
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    with tarfile.open(archive) as content:
        assert content.extractfile("database.dump").read() == b"PGDMP-synthetic-test"
        assert content.extractfile("state/secrets/token-encryption-key").read() == (state / "secrets/token-encryption-key").read_bytes()
        assert not any("backups/" in name or "cache/" in name for name in content.getnames())


def test_failed_database_dump_leaves_no_backup_archive(tmp_path, monkeypatch):
    state = tmp_path / "state"
    setup.prepare(ROOT, state, options())
    monkeypatch.setattr(setup.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=1))
    with pytest.raises(ValueError, match="no archive"):
        setup.backup(state, ["docker", "compose"], {})
    assert list((state / "backups").iterdir()) == []


def test_public_compose_is_one_container_with_private_internal_services():
    config = yaml.safe_load((ROOT / "compose.selfhost.yaml").read_text())
    assert set(config["services"]) == {"mailsec"}
    service = config["services"]["mailsec"]
    assert service["environment"]["MAILSEC_ENFORCEMENT_MODE"] == "passive"
    assert service["environment"]["MAILSEC_NOTIFICATIONS_ENABLED"] == "false"
    assert service["environment"]["WEB_RISK_API_KEY"] == ""
    assert service["read_only"] and service["cap_drop"] == ["ALL"]
    assert set(service["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "SETUID", "SETGID", "KILL"}
    assert service["ports"] == ["127.0.0.1:${MAILSEC_PORT:-8025}:8025"]
    assert service["volumes"][0] == "data:/data"
    assert not any("docker.sock" in mount for mount in service["volumes"])
    assert service["build"]["dockerfile"] == "Dockerfile.selfhost"
    assert "127.0.0.1" in (ROOT / "deploy/selfhost/clamd.conf").read_text()
    assert "listen_addresses = '127.0.0.1'" in (ROOT / "deploy/selfhost/postgresql.conf").read_text()
    assert "COPY organization.yaml" not in (ROOT / "Dockerfile.selfhost").read_text()


def test_start_builds_each_image_once_and_scrubs_inherited_pilot_settings(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(setup, "compose_command", lambda engine: ["podman-compose"])
    monkeypatch.setenv("MAILSEC_TENANT_ID", "unrelated-pilot")
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "unrelated-pilot")

    def run(command, **kwargs):
        assert "MAILSEC_TENANT_ID" not in kwargs["env"]
        assert "COMPOSE_PROJECT_NAME" not in kwargs["env"]
        calls.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(setup.subprocess, "run", run)
    assert setup.main(["start", "--runtime-dir", str(tmp_path / "state")]) == 0
    assert calls[0][-2:] == ["build", "mailsec"]
    assert calls[1][-3:] == ["up", "-d", "--no-build"]
    assert all("unrelated-pilot" not in command for command in calls)


PINNED_IMAGE = "ghcr.io/example/mailsec@sha256:" + "a" * 64


@pytest.mark.parametrize("image", [
    "ghcr.io/example/mailsec:latest", "ghcr.io/example/mailsec:0.4.0-alpha.5",
    "ghcr.io/example/mailsec@sha256:short", "https://ghcr.io/example/mailsec@sha256:" + "a" * 64,
    "ghcr.io/Example/mailsec@sha256:" + "a" * 64,
    "user:secret@ghcr.io/example/mailsec@sha256:" + "a" * 64,
    "ghcr.io/example/mailsec@sha256:" + "a" * 64 + "\n",
])
def test_prebuilt_image_requires_immutable_unambiguous_reference(tmp_path, image):
    with pytest.raises(ValueError, match="Image must"):
        setup.prepare(ROOT, tmp_path / "state", options("--image", image))


def test_prebuilt_image_persists_without_rotating_secrets_and_source_switch_is_explicit(tmp_path):
    state = tmp_path / "state"
    setup.prepare(ROOT, state, options())
    original = {path.name: path.read_bytes() for path in (state / "secrets").iterdir()}
    assert setup.prepare(ROOT, state, options("--image", PINNED_IMAGE))["image"] == PINNED_IMAGE
    assert setup.prepare(ROOT, state, options())["image"] == PINNED_IMAGE
    assert "MAILSEC_IMAGE='" + PINNED_IMAGE + "'" in (state / "compose.env").read_text()
    assert setup.prepare(ROOT, state, options("--build-from-source"))["image"] == ""
    assert original == {path.name: path.read_bytes() for path in (state / "secrets").iterdir()}


@pytest.mark.parametrize("offline", [False, True])
def test_prebuilt_start_pulls_exact_saved_image_and_never_builds(tmp_path, monkeypatch, offline):
    calls = []
    monkeypatch.setattr(setup, "compose_command", lambda engine: ["docker", "compose"])
    monkeypatch.setattr(setup, "check_host_isolation", lambda: None)
    monkeypatch.setenv("MAILSEC_IMAGE", "unrelated-image:latest")

    def run(command, **kwargs):
        assert "MAILSEC_IMAGE" not in kwargs["env"]
        calls.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(setup.subprocess, "run", run)
    state = tmp_path / "state"
    setup.prepare(ROOT, state, options("--image", PINNED_IMAGE))
    extra = ["--no-pull"] if offline else []
    assert setup.main(["start", "--runtime-dir", str(state), *extra]) == 0
    assert len(calls) == (1 if offline else 2)
    if not offline:
        assert calls[0][-2:] == ["pull", "mailsec"]
    assert calls[-1][-3:] == ["up", "-d", "--no-build"]
    assert not any("build" in command for command in calls)


def test_failed_prebuilt_pull_does_not_start_or_fallback_to_a_source_build(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(setup, "compose_command", lambda engine: ["docker", "compose"])
    monkeypatch.setattr(setup, "check_host_isolation", lambda: None)

    def fail(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=7)

    monkeypatch.setattr(setup.subprocess, "run", fail)
    assert setup.main(["start", "--runtime-dir", str(tmp_path / "state"), "--image", PINNED_IMAGE]) == 7
    assert len(calls) == 1 and calls[0][-2:] == ["pull", "mailsec"]


def test_build_revision_changes_for_source_but_not_python_cache(tmp_path):
    package = tmp_path / "mailsec"
    package.mkdir()
    source = package / "example.py"
    source.write_text("VERSION = 1\n")
    before = setup.build_revision(tmp_path, ["mailsec"])
    cache = package / "__pycache__"
    cache.mkdir()
    (cache / "example.pyc").write_bytes(b"random bytecode")
    assert setup.build_revision(tmp_path, ["mailsec"]) == before
    source.write_text("VERSION = 2\n")
    assert setup.build_revision(tmp_path, ["mailsec"]) != before


def test_legacy_six_service_state_is_rejected_without_mutation(tmp_path):
    state = tmp_path / "old"
    state.mkdir()
    (state / setup.MARKER).write_text("Mailsec self-host state v1\n")
    (state / "important").write_text("unchanged")
    before = {p.name: p.read_bytes() for p in state.iterdir()}
    with pytest.raises(ValueError, match="Legacy six-service"):
        setup.prepare(ROOT, state, options())
    assert before == {p.name: p.read_bytes() for p in state.iterdir()}


def test_database_only_mode_is_explicit_and_persists_until_cleared(tmp_path):
    state = tmp_path / "state"
    config = setup.prepare(ROOT, state, options("--database-only"))
    assert config["database_only"] is True
    assert "MAILSEC_DATABASE_ONLY='true'" in (state / "compose.env").read_text()
    assert setup.prepare(ROOT, state, options())["database_only"] is True
    assert setup.prepare(ROOT, state, options("--no-database-only"))["database_only"] is False
    assert stat.S_IMODE((state / "organization.yaml").stat().st_mode) == 0o400
