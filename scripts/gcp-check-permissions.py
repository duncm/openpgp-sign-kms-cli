#!/usr/bin/env python3
"""Non-mutating runtime IAM checks. Does not prove deny overrides accidental grants."""
import importlib.util
import os
from pathlib import Path
import sys
spec=importlib.util.spec_from_file_location('keys',Path(__file__).with_name('gcp-test-keys.py'))
keys=importlib.util.module_from_spec(spec);spec.loader.exec_module(keys)

api=keys.Api()
current=keys.Keys(api,os.environ['GCP_PROJECT_ID'],'us-central1',os.environ['GITHUB_REPOSITORY'])
protection=sys.argv[1] if len(sys.argv)>1 else 'software'
required=['cloudkms.cryptoKeys.get','cloudkms.cryptoKeyVersions.create','cloudkms.cryptoKeyVersions.get','cloudkms.cryptoKeyVersions.list','cloudkms.cryptoKeyVersions.update','cloudkms.cryptoKeyVersions.destroy','cloudkms.cryptoKeyVersions.viewPublicKey','cloudkms.cryptoKeyVersions.useToSign']
forbidden=['cloudkms.cryptoKeys.setIamPolicy','cloudkms.cryptoKeys.update','cloudkms.cryptoKeys.delete','cloudkms.cryptoKeyVersions.restore','cloudkms.cryptoKeyVersions.useToVerify']
for parent in current.parents(protection):
    granted=set(api.call('POST',parent+':testIamPermissions',{'permissions':required+forbidden}).get('permissions',[]))
    if not set(required)<=granted or granted.intersection(forbidden):
        raise RuntimeError('unexpected test-key permissions: '+parent)
if protection=='software':
    for parent in current.parents('hsm'):
        granted=set(api.call('POST',parent+':testIamPermissions',{'permissions':required+forbidden}).get('permissions',[]))
        if granted.intersection(['cloudkms.cryptoKeyVersions.create','cloudkms.cryptoKeyVersions.useToSign','cloudkms.cryptoKeyVersions.viewPublicKey']+forbidden):
            raise RuntimeError('software identity can use HSM key: '+parent)
other=next(repo for repo in keys.REPOS if repo!=os.environ['GITHUB_REPOSITORY'])
foreign=keys.Keys(api,os.environ['GCP_PROJECT_ID'],'us-central1',other)
for parent in foreign.parents('software'):
    granted=api.call('POST',parent+':testIamPermissions',{'permissions':required+forbidden}).get('permissions',[])
    if granted:
        raise RuntimeError('cross-repository permissions: '+parent)
print('Runtime IAM allow/deny permission checks passed')
