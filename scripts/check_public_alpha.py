#!/usr/bin/env python3
"""Read-only, offline consistency checks for an unpublished public source candidate.

This neither prepares an installation nor authorizes publication. It does not run
provider, browser, database, image, dependency, or live-mailbox checks. It reads
only allowlisted public source and an optional release manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit

sys.dont_write_bytecode = True  # Keep this read-only checker from creating a sibling cache.
from export_release import REQUIRED_FILES, ReleaseError, read_regular  # noqa: E402

MARKDOWN_LINK = re.compile(r'!?\[[^\]]+\]\(([^)\s]+)(?:\s+"[^"]*")?\)')


def check_source(source: Path, *, require_manifest: bool = False) -> dict:
    if source.is_symlink():
        raise ReleaseError('Source root must not be a symbolic link')
    source = source.resolve()
    required = {name: read_regular(source, name) for name in REQUIRED_FILES}
    checks = []
    failures = []

    def check(name: str, passed: bool):
        (checks if passed else failures).append(name)

    package_version = tomllib.loads(required['pyproject.toml'].decode())['project']['version']
    matched = re.fullmatch(r'(\d+\.\d+\.\d+)a(\d+)', package_version)
    if not matched:
        raise ReleaseError('Expected an explicit alpha package version in pyproject.toml')
    release_version = f'{matched[1]}-alpha.{matched[2]}'
    image = f'localhost/mailsec-selfhost:{release_version}'
    check('runtime engine matches package version',
          bool(re.search(r'[\'\"]engine[\'\"]\s*:\s*[\'\"]' + re.escape(release_version)
                         + r'[\'\"]', read_regular(source, 'mailsec/config.py').decode())))
    check('API matches package version',
          f'version="{release_version}"' in read_regular(source, 'mailsec/api.py').decode())
    check('Compose image matches package version', image in required['compose.selfhost.yaml'].decode())
    check('OCI image label matches package version',
          f'org.opencontainers.image.version="{release_version}"' in required['Dockerfile.selfhost'].decode())
    workflow = required['.github/workflows/ci.yml'].decode()
    check('CI image references match package version', image in workflow and not re.search(
        r'localhost/mailsec-selfhost:(?!' + re.escape(release_version) + r'(?:\s|$))[^\s]+', workflow))
    check('CI runs real browser checks under Node 22',
          "node-version: '22'" in workflow and all(test in workflow for test in ('node tests/ui-smoke.mjs', 'node tests/questions-ui-smoke.mjs')))
    ci_projects = re.findall(r'--project-name\s+([a-zA-Z0-9_-]+)', workflow)
    valid_ci_project = (len(ci_projects) == 1 and bool(re.fullmatch(
        r'mailsec-selfhost(?:-[a-z0-9][a-z0-9_-]*)?', ci_projects[0])))
    check('CI project name is accepted by the installer', valid_ci_project)
    check('CI container lookup and cleanup use the installed project', valid_ci_project and all(
        text in workflow for text in (
            f'label=com.docker.compose.project={ci_projects[0]}',
            f'-p {ci_projects[0]} down --volumes --remove-orphans',
        )))
    check('CI keeps read-only repository permission', 'contents: read' in workflow and 'packages: write' not in workflow)
    check('CI does not publish containers or releases', not re.search(
        r'\b(?:docker|podman)\s+(?:push|manifest\s+push)\b|\bgh\s+release\s+create\b|push:\s*true', workflow))
    check('README names current alpha', release_version in required['README.md'].decode())
    check('changelog names current alpha', release_version in required['CHANGELOG.md'].decode())
    check('question editor ships with source', 'mailsec/static/question-editor.js' in required)
    check('question guide and release checklist ship with source',
          all(name in required for name in ('docs/detection-questions.md', 'docs/public-alpha-release.md')))

    missing_links = []
    for name, content in required.items():
        if not name.endswith('.md'):
            continue
        for match in MARKDOWN_LINK.finditer(content.decode()):
            target = match[1].strip('<>')
            parts = urlsplit(target)
            if parts.scheme or parts.netloc or not parts.path:
                continue
            candidate = (source / name).parent / unquote(parts.path)
            resolved = candidate.resolve()
            if not resolved.is_relative_to(source) or not candidate.exists():
                missing_links.append(name)
    check('all local Markdown link targets exist within source', not missing_links)
    if missing_links:
        failures.extend('broken local link in ' + name for name in sorted(set(missing_links)))

    manifest_path = source / 'RELEASE_MANIFEST.json'
    if manifest_path.exists() or manifest_path.is_symlink():
        manifest = json.loads(read_regular(source, 'RELEASE_MANIFEST.json'))
        entries = manifest.get('files', [])
        valid = isinstance(entries, list) and bool(entries)
        paths = set()
        if valid:
            for entry in entries:
                if not isinstance(entry, dict):
                    valid = False
                    break
                name = entry.get('path')
                if (not isinstance(name, str) or Path(name).is_absolute()
                        or '..' in Path(name).parts or name in paths):
                    valid = False
                    break
                paths.add(name)
                content = read_regular(source, name)
                if hashlib.sha256(content).hexdigest() != entry.get('sha256') or len(content) != entry.get('bytes'):
                    valid = False
                    break
        valid = valid and set(REQUIRED_FILES).union({'mailsec/config.py', 'mailsec/api.py'}).issubset(paths)
        ignored_caches = {'__pycache__', '.pytest_cache', '.ruff_cache', '.git'}
        actual_paths = {path.relative_to(source).as_posix() for path in source.rglob('*')
                        if not ignored_caches.intersection(path.relative_to(source).parts)
                        and (path.is_file() or path.is_symlink())}
        valid = valid and actual_paths == paths.union({'RELEASE_MANIFEST.json'})
        check('export manifest entries match all required source bytes', valid)
        check('export manifest records completed secret scan', manifest.get('checks', {}).get('gitleaks') == 'passed')
    else:
        check('export manifest present when required', not require_manifest)
    return {'ok': not failures, 'version': release_version, 'checks_passed': len(checks),
            'checks': checks, 'failures': failures,
            'scope': 'Offline source consistency only; tests, runtime, security scans, and publication are separate gates.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--require-manifest', action='store_true', help='Require and verify an exported source manifest')
    args = parser.parse_args(argv)
    try:
        report = check_source(args.source, require_manifest=args.require_manifest)
    except (ReleaseError, OSError, ValueError, KeyError, TypeError):
        # Do not echo source/config contents if a candidate is malformed.
        print(json.dumps({'ok': False, 'error': 'Public source is missing, malformed, or unsafe to read.'}))
        return 1
    print(json.dumps(report, indent=2))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
