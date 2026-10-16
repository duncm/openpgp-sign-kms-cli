import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('gcp_keys', Path(__file__).resolve().parents[1] / 'gcp-test-keys.py')
gcp = importlib.util.module_from_spec(spec); spec.loader.exec_module(gcp)

class Fake:
    def __init__(self):
        self.parents = {}; self.items = {}; self.calls = []; self.fail = set()
    def call(self, method, resource, body=None):
        self.calls.append((method, resource, body))
        if resource in self.fail:
            raise RuntimeError('test failure')
        if method == 'GET':
            return dict(self.parents.get(resource) or self.items[resource])
        if method == 'POST' and resource.endswith('/cryptoKeyVersions'):
            parent = resource.removesuffix('/cryptoKeyVersions')
            name = resource + '/' + str(len(self.items) + 1)
            item = dict(name=name, state='ENABLED', createTime='2020-01-01T00:00:00Z', **self.parents[parent]['versionTemplate'])
            self.items[name] = item
            return dict(item)
        name = resource.split('?')[0].removesuffix(':destroy')
        self.items[name]['state'] = 'DISABLED' if method == 'PATCH' else 'DESTROY_SCHEDULED'
        return dict(self.items[name])
    def versions(self, parent):
        return iter([v for n,v in self.items.items() if n.startswith(parent + '/')])

class KeyTests(unittest.TestCase):
    def setUp(self):
        self.api = Fake()
        self.keys = gcp.Keys(self.api, 'test-project', 'us-central1', 'duncm/openpgp-sign-kms')
        for protection in ['software', 'hsm']:
            for parent, algorithm in self.keys.parents(protection).items():
                self.api.parents[parent] = dict(name=parent, purpose='ASYMMETRIC_SIGN', destroyScheduledDuration='86400s', versionTemplate=dict(algorithm=algorithm, protectionLevel=protection.upper()), labels={'project':'openpgp-sign-kms','purpose':'integration-temporary','repository':'action','managed-by':'openpgp-sign-kms-ci'})
    def create(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'journal'
            names = self.keys.create('software', path)
            records = [json.loads(s) for s in path.read_text().splitlines()]
            self.assertEqual(names, [r['name'] for r in records])
            return records
    def test_create_cleanup_and_repeat(self):
        records = self.create()
        self.keys.cleanup(records)
        self.assertTrue(all(v['state']=='DESTROY_SCHEDULED' for v in self.api.items.values()))
        self.api.calls.clear(); self.keys.cleanup(records)
        self.assertTrue(all(c[0]=='GET' for c in self.api.calls))
    def test_dry_run_and_orphans(self):
        self.create()
        self.keys.sweep(True)
        self.assertTrue(all(v['state']=='ENABLED' for v in self.api.items.values()))
        self.keys.sweep(False)
        self.assertTrue(all(v['state']=='DESTROY_SCHEDULED' for v in self.api.items.values()))
    def test_recent_versions_survive_sweep(self):
        self.create()
        for v in self.api.items.values():
            v['createTime'] = gcp.dt.datetime.now(gcp.dt.timezone.utc).isoformat()
        self.keys.sweep(False)
        self.assertTrue(all(v['state']=='ENABLED' for v in self.api.items.values()))
    def test_partial_failure_does_not_skip_other_versions(self):
        records = self.create(); self.api.fail.add(records[0]['name'])
        with self.assertRaises(RuntimeError): self.keys.cleanup(records)
        self.assertEqual(self.api.items[records[1]['name']]['state'], 'DESTROY_SCHEDULED')
    def test_parent_drift_and_outside_resource_rejected(self):
        records = self.create()
        parent = records[0]['name'].rsplit('/cryptoKeyVersions/',1)[0]
        self.api.parents[parent]['versionTemplate']['algorithm'] = 'RSA_SIGN_PSS_3072_SHA256'
        with self.assertRaises(RuntimeError): self.keys.cleanup(records)
        with self.assertRaises(ValueError): self.keys.cleanup_one(records[0]['name'].replace('test-project','other-project'),'software')
    def test_creation_failure_preserves_journal(self):
        parents = list(self.keys.parents('software'))
        self.api.fail.add(parents[1] + '/cryptoKeyVersions')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'journal'
            with self.assertRaises(RuntimeError): self.keys.create('software', path)
            records = [json.loads(s) for s in path.read_text().splitlines()]
            self.assertEqual(len(records),1)
            self.keys.cleanup(records)
    def test_future_malformed_and_foreign_metadata(self):
        records = self.create()
        self.api.items[records[0]['name']]['algorithm'] = 'EC_SIGN_P256_SHA256'
        with self.assertRaises(RuntimeError): self.keys.cleanup(records)
        self.assertEqual(self.api.items[records[0]['name']]['state'],'ENABLED')
    def test_pagination(self):
        api = object.__new__(gcp.Api)
        pages = iter([{'cryptoKeyVersions':[{'name':'one'}],'nextPageToken':'next+/='},{'cryptoKeyVersions':[{'name':'two'}]}])
        paths=[]
        def call(method, resource, body=None):
            paths.append(resource); return next(pages)
        api.call = call
        self.assertEqual([v['name'] for v in api.versions('parent')],['one','two'])
        self.assertIn('pageToken=next%2B%2F%3D',paths[1])
    def test_malformed_journal_does_not_skip_valid_records(self):
        records = self.create()
        with self.assertRaises(RuntimeError): self.keys.cleanup([42, *records])
        self.assertTrue(all(v['state']=='DESTROY_SCHEDULED' for v in self.api.items.values()))
    def test_algorithm_must_be_provisioned(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError): self.keys.create('hsm', Path(directory)/'state', ['ed25519'])
        self.assertFalse(self.api.calls)
    def test_wrong_region_or_repository_rejected(self):
        with self.assertRaises(ValueError): gcp.Keys(self.api,'test-project','us-west1','duncm/openpgp-sign-kms')
        with self.assertRaises(KeyError): gcp.Keys(self.api,'test-project','us-central1','attacker/repo')

if __name__ == '__main__': unittest.main()
