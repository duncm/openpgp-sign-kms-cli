#!/usr/bin/env python3
"""Wait for a bounded, exact Google KMS signing audit marker. Never log credentials."""
import base64
import json
import os
import subprocess
import sys
import time

def check(description, key=None):
    marker = 'description/' + base64.urlsafe_b64encode(description.encode()).decode().rstrip('=')
    filters = ['protoPayload.serviceName="cloudkms.googleapis.com"', 'protoPayload.methodName="AsymmetricSign"', 'protoPayload.requestMetadata.callerSuppliedUserAgent:' + json.dumps(marker)]
    if key:
        filters.append('protoPayload.resourceName=' + json.dumps(key))
    deadline = time.monotonic() + 300
    while True:
        entries = json.loads(subprocess.check_output(['gcloud','logging','read',' AND '.join(filters), '--project',os.environ['GCP_PROJECT_ID'],'--freshness=1h','--limit=50','--format=json'], text=True))
        if any(marker in e.get('protoPayload',{}).get('requestMetadata',{}).get('callerSuppliedUserAgent','') for e in entries):
            print('Google signing audit marker verified')
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('Google signing audit marker not found within 5 minutes; check KMS DATA_READ logging and log-reader permissions')
        time.sleep(10)

if __name__ == '__main__':
    check(sys.argv[1], sys.argv[2] if len(sys.argv)>2 else None)
