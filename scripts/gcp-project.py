#!/usr/bin/env python3
"""Render reviewable project policies and administrator commands; never calls Google APIs."""
import argparse
import json
from pathlib import Path
import re
import shlex

ALGORITHMS = {'rsa2048':'RSA_SIGN_PKCS1_2048_SHA256','rsa3072':'RSA_SIGN_PKCS1_3072_SHA256','rsa4096':'RSA_SIGN_PKCS1_4096_SHA256','rsa4096-sha512':'RSA_SIGN_PKCS1_4096_SHA512','ed25519':'EC_SIGN_ED25519'}
POOL = 'openpgp-github'
PROVIDERS = {'software': 'software', 'hsm': 'hsm-smoke'}

def federation_condition(config, hsm):
    environment = 'gcp-hsm' if hsm else 'gcp-integration'
    repos = ' || '.join(f"(assertion.repository_id == '{r['id']}' && assertion.repository == '{r['name']}')" for r in config['repositories'].values())
    base = f"assertion.repository_owner_id == '{config['owner_id']}' && ({repos}) && assertion.environment == '{environment}'"
    if hsm:
        event = "assertion.event_name == 'workflow_dispatch' && assertion.ref == 'refs/heads/main' && assertion.workflow_ref == assertion.repository + '/.github/workflows/gcp-hsm.yml@refs/heads/main'"
    else:
        manual = "assertion.event_name == 'workflow_dispatch' && assertion.ref == 'refs/heads/main' && (assertion.workflow_ref == assertion.repository + '/.github/workflows/gcp-integration.yml@refs/heads/main' || assertion.workflow_ref == assertion.repository + '/.github/workflows/gcp-cleanup.yml@refs/heads/main')"
        scheduled = "assertion.event_name == 'schedule' && assertion.ref == 'refs/heads/main' && assertion.workflow_ref == assertion.repository + '/.github/workflows/gcp-cleanup.yml@refs/heads/main'"
        release = "assertion.event_name == 'push' && assertion.ref.matches('^refs/tags/v[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?$') && assertion.workflow_ref == assertion.repository + '/.github/workflows/release.yml@' + assertion.ref && 'job_workflow_ref' in assertion && assertion.job_workflow_ref == assertion.repository + '/.github/workflows/gcp-integration.yml@' + assertion.ref"
        event = f'({manual}) || ({scheduled}) || ({release})'
    return base + ' && (' + event + ')'

def render(config, output):
    project, number, org = (config[k] for k in ['project_id','project_number','organization_id'])
    if not re.fullmatch(r'[a-z][a-z0-9-]{4,28}[a-z0-9]',project): raise ValueError('invalid project ID')
    for value in [number,org,config['owner_id'],*(r['id'] for r in config['repositories'].values())]:
        if not re.fullmatch(r'[0-9]+',value): raise ValueError('numeric ID required')
    if config['location'] != 'us-central1': raise ValueError('test location is us-central1')
    if not re.fullmatch(r'[A-Za-z0-9_.+@-]+',config['admin_group']) or '@' not in config['admin_group']: raise ValueError('invalid administrator group')
    if set(config['repositories']) != {'cli','action'}: raise ValueError('expected cli and action repositories')
    for r in config['repositories'].values():
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',r['name']): raise ValueError('invalid repository')
    for identifier in [POOL, *PROVIDERS.values()]:
        if not re.fullmatch(r'[a-z0-9-]{4,32}', identifier) or identifier.startswith('gcp-'):
            raise ValueError('invalid workload identity pool/provider ID: ' + identifier)
    output.mkdir(parents=True, exist_ok=True)
    def write(name, value):
        (output/name).write_text(json.dumps(value,indent=2)+'\n')
    def role(name, permissions):
        write(name+'.json',{'title':name,'description':'OpenPGP dedicated integration project; see Google setup guide','stage':'GA','includedPermissions':permissions})
    read=['cloudkms.cryptoKeys.get','cloudkms.cryptoKeyVersions.get','cloudkms.cryptoKeyVersions.list']
    cleanup=read+['cloudkms.cryptoKeyVersions.update','cloudkms.cryptoKeyVersions.destroy']
    runtime=cleanup+['cloudkms.cryptoKeyVersions.create','cloudkms.cryptoKeyVersions.viewPublicKey','cloudkms.cryptoKeyVersions.useToSign']
    role('openpgpIntegration',runtime)
    role('openpgpCleanup',cleanup)
    role('openpgpAuditReader',['logging.logEntries.list','logging.privateLogEntries.list','resourcemanager.projects.get','serviceusage.services.use'])
    role('openpgpSigner',['cloudkms.cryptoKeyVersions.get','cloudkms.cryptoKeyVersions.viewPublicKey','cloudkms.cryptoKeyVersions.useToSign'])
    def policy(constraint, rules):
        write('policy-'+constraint+'.json',{'name':f'projects/{number}/policies/{constraint}','spec':{'rules':rules}})
    for constraint in ['iam.managed.disableServiceAccountKeyCreation','iam.managed.disableServiceAccountKeyUpload','iam.automaticIamGrantsForDefaultServiceAccounts']:
        policy(constraint,[{'enforce':True}])
    policy('iam.managed.allowedPolicyMembers',[{'enforce':True,'parameters':{'allowedPrincipalSets':[f'//cloudresourcemanager.googleapis.com/organizations/{org}']}}])
    policy('iam.workloadIdentityPoolProviders',[{'values':{'allowedValues':['https://token.actions.githubusercontent.com']}}])
    policy('gcp.resourceLocations',[{'values':{'allowedValues':['in:us-central1-locations']}}])
    # Logging/IAM/Monitoring are essential dependencies excluded from this constraint.
    policy('gcp.restrictServiceUsage',[{'values':{'allowedValues':['cloudkms.googleapis.com']}}])
    constraint='custom.openpgpIntegrationKeys'
    write('custom-kms-constraint.json',{
        'name':f'organizations/{org}/customConstraints/{constraint}',
        'resourceTypes':['cloudkms.googleapis.com/CryptoKey'],'methodTypes':['CREATE','UPDATE'],
        'condition':"resource.purpose == 'ASYMMETRIC_SIGN' && resource.versionTemplate.algorithm in " + repr(list(ALGORITHMS.values())) + " && resource.versionTemplate.protectionLevel in ['SOFTWARE', 'HSM'] && (resource.versionTemplate.algorithm != 'EC_SIGN_ED25519' || resource.versionTemplate.protectionLevel == 'SOFTWARE') && resource.destroyScheduledDuration == duration('86400s') && !resource.importOnly",
        'actionType':'ALLOW','displayName':'Only approved OpenPGP integration keys',
        'description':'Dedicated test project: generated RSA/Ed25519 signing keys and a 24-hour destruction delay.'})
    policy(constraint,[{'enforce':True}])
    accounts={f'{repo}-{level}':f'openpgp-{repo}-{level}@{project}.iam.gserviceaccount.com' for repo in config['repositories'] for level in ['software','hsm']}
    principals=['principal://iam.googleapis.com/projects/-/serviceAccounts/'+a for a in accounts.values()]
    denied=['cloudkms.googleapis.com/cryptoKeys.create','cloudkms.googleapis.com/cryptoKeys.update','cloudkms.googleapis.com/cryptoKeys.delete','cloudkms.googleapis.com/cryptoKeys.setIamPolicy','cloudkms.googleapis.com/keyRings.create','cloudkms.googleapis.com/keyRings.delete','cloudkms.googleapis.com/keyRings.setIamPolicy','cloudkms.googleapis.com/cryptoKeyVersions.restore','cloudkms.googleapis.com/cryptoKeyVersions.trustedImportExport','cloudkms.googleapis.com/importJobs.create','cloudkms.googleapis.com/importJobs.setIamPolicy','cloudkms.googleapis.com/cryptoKeyVersions.useToDecrypt','cloudkms.googleapis.com/cryptoKeyVersions.useToEncrypt','cloudkms.googleapis.com/cryptoKeyVersions.useToVerify',
        'cloudresourcemanager.googleapis.com/projects.setIamPolicy','cloudresourcemanager.googleapis.com/projects.delete','cloudresourcemanager.googleapis.com/projects.move',
        'iam.googleapis.com/roles.create','iam.googleapis.com/roles.update','iam.googleapis.com/roles.delete','iam.googleapis.com/roles.undelete','iam.googleapis.com/serviceAccounts.setIamPolicy','iam.googleapis.com/serviceAccounts.create','iam.googleapis.com/serviceAccounts.getAccessToken','iam.googleapis.com/serviceAccounts.getOpenIdToken','iam.googleapis.com/serviceAccounts.signBlob','iam.googleapis.com/serviceAccounts.signJwt','iam.googleapis.com/serviceAccounts.actAs',
        'iam.googleapis.com/workloadIdentityPools.*','iam.googleapis.com/workloadIdentityPoolProviders.*','orgpolicy.googleapis.com/policies.*','orgpolicy.googleapis.com/policy.set','serviceusage.googleapis.com/services.enable','serviceusage.googleapis.com/services.disable']
    # Custom constraint definitions live on organizations. Their permissions cannot
    # appear in this project-attached deny policy; CI has no organization-level grants.
    # Project policy create/update/delete remains covered by policies.* and policy.set.
    # importJobs.setIamPolicy is not supported by IAM deny; no corresponding allow is granted.
    denied.remove('cloudkms.googleapis.com/importJobs.setIamPolicy')
    write('deny-policy.json',{'displayName':'OpenPGP integration signing and administration boundary','rules':[
        {'description':'Unexpected identities cannot sign even if granted a signer role','denyRule':{'deniedPrincipals':['principalSet://goog/public:all'],'exceptionPrincipals':principals+['principalSet://goog/group/'+config['admin_group']],'deniedPermissions':['cloudkms.googleapis.com/cryptoKeyVersions.useToSign']}},
        {'description':'Workflow accounts cannot administer IAM, keys, federation or services','denyRule':{'deniedPrincipals':principals,'deniedPermissions':denied}}
    ]})
    commands=['#!/usr/bin/env bash','set -euo pipefail','cd -- "$(dirname -- "$0")"','# Review this file and inherited policies before running. One-time provisioning; does not replace existing IAM policies.']
    def cmd(*args): commands.append(shlex.join(str(a) for a in args))
    cmd('gcloud','iam','workload-identity-pools','create',POOL,'--project='+project,'--location=global','--display-name=OpenPGP GitHub integration')
    for hsm in [False,True]:
        level='hsm' if hsm else 'software'
        condition=federation_condition(config,hsm)
        mapping='google.subject=assertion.sub,attribute.repository_id=assertion.repository_id,attribute.environment=assertion.environment,attribute.workload=assertion.repository_id+"_"+assertion.environment'
        provider=f'projects/{number}/locations/global/workloadIdentityPools/{POOL}/providers/{PROVIDERS[level]}'
        write('provider-'+level+'.json',{'name':provider,'oidc':{'issuerUri':'https://token.actions.githubusercontent.com','allowedAudiences':['https://iam.googleapis.com/'+provider]},'attributeMapping':{'google.subject':'assertion.sub','attribute.repository_id':'assertion.repository_id','attribute.environment':'assertion.environment','attribute.workload':'assertion.repository_id+"_"+assertion.environment'},'attributeCondition':condition})
        cmd('gcloud','iam','workload-identity-pools','providers','create-oidc',PROVIDERS[level],'--project='+project,'--location=global','--workload-identity-pool='+POOL,'--issuer-uri=https://token.actions.githubusercontent.com','--allowed-audiences=https://iam.googleapis.com/'+provider,'--attribute-mapping='+mapping,'--attribute-condition='+condition)
    for name in ['openpgpIntegration','openpgpCleanup','openpgpAuditReader']:
        cmd('gcloud','iam','roles','create',name,'--project='+project,'--file='+name+'.json')
    for label,account in accounts.items():
        repo,level=label.split('-');r=config['repositories'][repo];environment='gcp-hsm' if level=='hsm' else 'gcp-integration'
        cmd('gcloud','iam','service-accounts','create',account.split('@')[0],'--project='+project)
        member=f'principalSet://iam.googleapis.com/projects/{number}/locations/global/workloadIdentityPools/{POOL}/attribute.workload/{r["id"]}_{environment}'
        cmd('gcloud','iam','service-accounts','add-iam-policy-binding',account,'--project='+project,'--role=roles/iam.workloadIdentityUser','--member='+member)
        cmd('gcloud','projects','add-iam-policy-binding',project,'--role=projects/'+project+'/roles/openpgpAuditReader','--member=serviceAccount:'+account,'--condition=None')
        ring='openpgp-'+repo+'-'+level
        cmd('gcloud','kms','keyrings','create',ring,'--project='+project,'--location=us-central1')
        kinds=['rsa3072'] if level=='hsm' else list(ALGORITHMS) if repo=='cli' else ['rsa3072','ed25519']
        for kind in kinds:
            flags=['--project='+project,'--location=us-central1','--keyring='+ring]
            cmd('gcloud','kms','keys','create',kind,*flags,'--purpose=asymmetric-signing','--default-algorithm='+ALGORITHMS[kind].lower().replace('_','-'),'--protection-level='+level,'--skip-initial-version-creation','--destroy-scheduled-duration=24h','--labels=project=openpgp-sign-kms,purpose=integration-temporary,repository='+repo+',managed-by=openpgp-sign-kms-ci')
            cmd('gcloud','kms','keys','add-iam-policy-binding',kind,*flags,'--role=projects/'+project+'/roles/openpgpIntegration','--member=serviceAccount:'+account)
            if level=='hsm':
                cmd('gcloud','kms','keys','add-iam-policy-binding',kind,*flags,'--role=projects/'+project+'/roles/openpgpCleanup','--member=serviceAccount:'+accounts[repo+'-software'])
    (output/'provision-runtime.sh').write_text('\n'.join(commands)+'\n')
    write('github-environments.json',{repo:{environment:{'GCP_PROJECT_ID':project,'GCP_WORKLOAD_IDENTITY_PROVIDER':f'projects/{number}/locations/global/workloadIdentityPools/{POOL}/providers/{PROVIDERS[level]}','GCP_SERVICE_ACCOUNT':accounts[repo+'-'+level]} for environment,level in [('gcp-integration','software'),('gcp-hsm','hsm')]} for repo in config['repositories']})
    return accounts

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    render(json.loads(Path(a.config).read_text()),Path(a.output))
    print('Rendered locally. No Google Cloud changes applied.')

if __name__=='__main__': main()
