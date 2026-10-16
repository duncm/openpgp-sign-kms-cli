#!/usr/bin/env python3
"""Temporary Google KMS versions in an administrator-provisioned allowlist.
No key creation, IAM edits, restoration, or broad resource discovery.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.request

ALGORITHMS = {
    'rsa2048': 'RSA_SIGN_PKCS1_2048_SHA256',
    'rsa3072': 'RSA_SIGN_PKCS1_3072_SHA256',
    'rsa4096': 'RSA_SIGN_PKCS1_4096_SHA256',
    'rsa4096-sha512': 'RSA_SIGN_PKCS1_4096_SHA512',
    'ed25519': 'EC_SIGN_ED25519',
}
REPOS = {'duncm/openpgp-sign-kms-cli': 'cli', 'duncm/openpgp-sign-kms': 'action'}
TTL = 24 * 3600


def timestamp(value):
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


class Api:
    def __init__(self):
        self.token = subprocess.check_output(['gcloud', 'auth', 'print-access-token', '--quiet'], text=True).strip()

    def call(self, method, resource, body=None):
        # Deliberately no automatic retries: create-version is not idempotent.
        req = urllib.request.Request('https://cloudkms.googleapis.com/v1/' + resource,
            data=None if body is None else json.dumps(body).encode(), method=method,
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.load(response)

    def versions(self, parent):
        token = ''
        while True:
            from urllib.parse import urlencode
            response = self.call('GET', parent + '/cryptoKeyVersions?' + urlencode({'pageSize': 1000, 'pageToken': token}))
            yield from response.get('cryptoKeyVersions', [])
            token = response.get('nextPageToken', '')
            if not token:
                break


class Keys:
    def __init__(self, api, project, location, repository):
        if not re.fullmatch(r'[a-z][a-z0-9-]{4,28}[a-z0-9]', project):
            raise ValueError('GCP_PROJECT_ID must be a project ID, not a number or URL')
        if location != 'us-central1':
            raise ValueError('integration keys are restricted to us-central1')
        self.api, self.project, self.location, self.repository = api, project, location, repository
        self.repo = REPOS[repository]

    def parents(self, protection):
        kinds = ['rsa3072'] if protection == 'hsm' else list(ALGORITHMS) if self.repo == 'cli' else ['rsa3072', 'ed25519']
        return {f'projects/{self.project}/locations/{self.location}/keyRings/openpgp-{self.repo}-{protection}/cryptoKeys/{kind}': ALGORITHMS[kind] for kind in kinds}

    def validate_parent(self, parent, protection):
        expected = self.parents(protection)[parent]
        key = self.api.call('GET', parent)
        labels = key.get('labels', {})
        template = key.get('versionTemplate', {})
        if (key.get('name') != parent or key.get('purpose') != 'ASYMMETRIC_SIGN'
            or template.get('algorithm') != expected or template.get('protectionLevel') != protection.upper()
            or key.get('destroyScheduledDuration') != '86400s' or key.get('importOnly', False)
            or key.get('rotationPeriod') or key.get('nextRotationTime')
            or any(labels.get(k) != v for k, v in {'project': 'openpgp-sign-kms', 'purpose': 'integration-temporary', 'repository': self.repo, 'managed-by': 'openpgp-sign-kms-ci'}.items())):
            raise ValueError('unexpected test-key configuration: ' + parent)
        return expected

    def validate_version(self, version, parent, protection, algorithm):
        if (not re.fullmatch(re.escape(parent) + r'/cryptoKeyVersions/[1-9][0-9]*', version.get('name', ''))
            or version.get('algorithm') != algorithm or version.get('protectionLevel') != protection.upper()
            or version.get('importJob') or version.get('importTime')):
            raise ValueError('unexpected test-key version metadata')
        timestamp(version['createTime'])

    def create(self, protection, state, kinds=None):
        result = []
        allowed = {p.rsplit('/', 1)[1] for p in self.parents(protection)}
        if kinds and not set(kinds) <= allowed:
            raise ValueError('requested algorithm is not provisioned for this repository/protection')
        state = Path(state)
        state.parent.mkdir(parents=True, exist_ok=True)
        # Never overwrite a journal left by an earlier creation attempt.
        with state.open('x') as journal:
            for parent in self.parents(protection):
                if kinds and parent.rsplit("/", 1)[1] not in kinds:
                    continue
                algorithm = self.validate_parent(parent, protection)
                version = self.api.call('POST', parent + '/cryptoKeyVersions', {})
                name = version['name']
                # Record before readiness checks. A lost HTTP response is recovered by sweep.
                journal.write(json.dumps({'name': name, 'protection': protection}) + '\n')
                journal.flush()
                os.fsync(journal.fileno())
                self.validate_version(version, parent, protection, algorithm)
                deadline = time.monotonic() + 300
                while version['state'] == 'PENDING_GENERATION' and time.monotonic() < deadline:
                    time.sleep(3)
                    version = self.api.call('GET', name)
                    self.validate_version(version, parent, protection, algorithm)
                if version['state'] != 'ENABLED':
                    raise RuntimeError('key version did not become ENABLED: ' + name)
                result.append(name)
                print('Created ' + name, flush=True)
        return result

    def cleanup_one(self, name, protection, dry_run=False, expired=False):
        parent = name.rsplit('/cryptoKeyVersions/', 1)[0]
        if parent not in self.parents(protection):
            raise ValueError('version outside configured allowlist: ' + name)
        algorithm = self.validate_parent(parent, protection)
        version = self.api.call('GET', name)
        self.validate_version(version, parent, protection, algorithm)
        if expired and timestamp(version['createTime']) > time.time() - TTL:
            return
        if version['state'] in ('DESTROY_SCHEDULED', 'DESTROYED', 'GENERATION_FAILED', 'IMPORT_FAILED'):
            return
        if dry_run:
            print('Would destroy ' + name)
            return
        # A bounded readiness wait covers interrupted key generation.
        deadline = time.monotonic() + 300
        while version['state'] == 'PENDING_GENERATION' and time.monotonic() < deadline:
            time.sleep(3)
            version = self.api.call('GET', name)
            self.validate_version(version, parent, protection, algorithm)
        if version['state'] == 'ENABLED':
            self.api.call('PATCH', name + '?updateMask=state', {'name': name, 'state': 'DISABLED'})
        elif version['state'] != 'DISABLED':
            raise RuntimeError('cannot clean up version in state ' + version['state'])
        self.api.call('POST', name + ':destroy', {})
        print('Scheduled destruction ' + name, flush=True)

    def cleanup(self, records, dry_run=False, expired=False):
        failures = []
        for record in records:
            try:
                self.cleanup_one(record['name'], record['protection'], dry_run, expired)
            except Exception as error:
                label = record.get('name', '<invalid>') if isinstance(record, dict) else '<invalid>'
                failures.append(f"{label}: {error}")
        if failures:
            raise RuntimeError('\n'.join(failures))

    def sweep(self, dry_run):
        failures = []
        for protection in ('software', 'hsm'):
            for parent in self.parents(protection):
                try:
                    self.validate_parent(parent, protection)
                    self.cleanup(({'name': v['name'], 'protection': protection} for v in self.api.versions(parent)), dry_run, expired=True)
                except Exception as error:
                    failures.append(f'{parent}: {error}')
        if failures:
            raise RuntimeError('\n'.join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['create', 'cleanup', 'sweep'])
    parser.add_argument('--protection', choices=['software', 'hsm'], default='software')
    parser.add_argument('--state')
    parser.add_argument('--kind', action='append', choices=list(ALGORITHMS))
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    keys = Keys(Api(), os.environ['GCP_PROJECT_ID'], os.environ.get('GCP_LOCATION', 'us-central1'), os.environ['GITHUB_REPOSITORY'])
    if args.operation == 'create':
        versions = keys.create(args.protection, args.state, args.kind)
        with open(os.environ['GITHUB_ENV'], 'a') as f:
            f.write('GCP_KEY_VERSIONS=' + json.dumps(versions) + '\n')
            if versions:
                f.write('GCP_KEY_VERSION=' + versions[0] + '\n')
    elif args.operation == 'cleanup':
        if args.state and Path(args.state).exists():
            records, errors = [], []
            for line in Path(args.state).read_text().splitlines():
                try:
                    records.append(json.loads(line))
                except ValueError as error:
                    errors.append(str(error))
            keys.cleanup(records, args.dry_run)
            if errors:
                raise RuntimeError('malformed journal records: ' + '; '.join(errors))
    else:
        keys.sweep(args.dry_run)

if __name__ == '__main__':
    main()
