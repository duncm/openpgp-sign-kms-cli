#!/usr/bin/env python3
"""Merge KMS DATA_READ into a local IAM policy snapshot; no cloud writes."""
import json
from pathlib import Path
import sys

def merge(policy):
    configs=policy.setdefault('auditConfigs',[])
    for config in configs:
        if config['service'] in ('allServices','cloudkms.googleapis.com'):
            for entry in config.get('auditLogConfigs',[]):
                if entry.get('logType')=='DATA_READ' and entry.get('exemptedMembers'):
                    raise ValueError('DATA_READ exemptions require administrator review')
    kms=next((c for c in configs if c['service']=='cloudkms.googleapis.com'),None)
    if kms is None:
        kms={'service':'cloudkms.googleapis.com','auditLogConfigs':[]};configs.append(kms)
    if not any(c.get('logType')=='DATA_READ' for c in kms.setdefault('auditLogConfigs',[])):
        kms['auditLogConfigs'].append({'logType':'DATA_READ'})
    return policy

if __name__=='__main__':
    policy=json.loads(Path(sys.argv[1]).read_text())
    Path(sys.argv[2]).write_text(json.dumps(merge(policy),indent=2)+'\n')
