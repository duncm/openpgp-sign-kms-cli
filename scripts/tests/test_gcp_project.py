import importlib.util
import json
from pathlib import Path
import tempfile
import shlex
from unittest import mock
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
    def test_provider_commands_audiences_and_environment_values_agree(self):
        config=json.loads((ROOT/'docs/gcp/project.example.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp);project.render(config,out)
            commands=[shlex.split(line) for line in (out/'provision-runtime.sh').read_text().splitlines() if line.startswith('gcloud ')]
            providers=[c for c in commands if c[:4]==['gcloud','iam','workload-identity-pools','providers']]
            self.assertEqual([c[5] for c in providers],['software','hsm-smoke'])
            environments=json.loads((out/'github-environments.json').read_text())
            for command,mode,environment in zip(providers,['software','hsm'],['gcp-integration','gcp-hsm']):
                identifier=command[5]
                self.assertRegex(identifier,r'^[a-z0-9-]{4,32}$')
                self.assertFalse(identifier.startswith('gcp-'))
                provider=json.loads((out/f'provider-{mode}.json').read_text())
                self.assertTrue(provider['name'].endswith('/providers/'+identifier))
                audience='https://iam.googleapis.com/'+provider['name']
                self.assertEqual(provider['oidc']['allowedAudiences'],[audience])
                self.assertIn('--allowed-audiences='+audience,command)
                for repo in ['cli','action']:
                    self.assertEqual(environments[repo][environment]['GCP_WORKLOAD_IDENTITY_PROVIDER'],provider['name'])
    def test_invalid_provider_id_rejected_before_writing(self):
        config=json.loads((ROOT/'docs/gcp/project.example.json').read_text())
        for identifier in ['hsm','x'*33,'Uppercase','bad_name','gcp-reserved']:
            with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(project.PROVIDERS,{'hsm':identifier}):
                out=Path(tmp)/'output'
                with self.assertRaisesRegex(ValueError,'pool/provider ID'):
                    project.render(config,out)
                self.assertFalse(out.exists())
    def test_reject_injection(self):
        config=json.loads((ROOT/'docs/gcp/project.example.json').read_text())
        config['organization_id']='123; touch bad'
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):project.render(config,Path(tmp))

if __name__=='__main__':unittest.main()
