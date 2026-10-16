import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('project',ROOT/'scripts/gcp-project.py')
project=importlib.util.module_from_spec(spec);spec.loader.exec_module(project)
class ProjectTests(unittest.TestCase):
    def test_templates_and_exact_resource_roles(self):
        config=json.loads((ROOT/'docs/gcp/project.example.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp);accounts=project.render(config,out)
            self.assertEqual(len(accounts),4)
            runtime=json.loads((out/'openpgpIntegration.json').read_text())['includedPermissions']
            self.assertNotIn('cloudkms.cryptoKeys.create',runtime)
            self.assertFalse(any('IamPolicy' in p for p in runtime))
            cleanup=json.loads((out/'openpgpCleanup.json').read_text())['includedPermissions']
            self.assertNotIn('cloudkms.cryptoKeyVersions.create',cleanup)
            self.assertNotIn('cloudkms.cryptoKeyVersions.useToSign',cleanup)
            deny=json.loads((out/'deny-policy.json').read_text())['rules'][0]['denyRule']
            self.assertEqual(deny['deniedPrincipals'],['principalSet://goog/public:all'])
            self.assertEqual(len(deny['exceptionPrincipals']),5)
            for mode in ['software','hsm']:
                provider=json.loads((out/f'provider-{mode}.json').read_text())
                self.assertEqual(provider['attributeMapping']['google.subject'],'assertion.sub')
                self.assertIn('assertion.environment',provider['attributeMapping']['attribute.workload'])
                condition=provider['attributeCondition']
                self.assertLess(len(condition),4096)
                self.assertNotIn("== 'pull_request'",condition)
                for repo in config['repositories'].values(): self.assertIn(repo['id'],condition)
            self.assertNotIn("== 'push'",json.loads((out/'provider-hsm.json').read_text())['attributeCondition'])
            self.assertIn('job_workflow_ref',json.loads((out/'provider-software.json').read_text())['attributeCondition'])
            script=(out/'provision-runtime.sh').read_text()
            self.assertEqual(script.count('--skip-initial-version-creation'),9)
            self.assertNotIn('service-accounts keys create',script)
    def test_reject_injection(self):
        config=json.loads((ROOT/'docs/gcp/project.example.json').read_text())
        config['organization_id']='123; touch bad'
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):project.render(config,Path(tmp))

if __name__=='__main__':unittest.main()
