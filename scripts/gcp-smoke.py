#!/usr/bin/env python3
"""One manual HSM export/sign/verify operation; no full matrix."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid
cli = str(Path(sys.argv[1]).resolve())
keys = json.loads(os.environ['GCP_KEY_VERSIONS'])
assert len(keys) == 1
key = keys[0]
marker = 'hsm-smoke-' + str(uuid.uuid4())
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp); home = root/'gnupg'; home.mkdir(mode=0o700)
    env = dict(os.environ, GNUPGHOME=str(home))
    def run(args): subprocess.run(args, cwd=root, env=env, check=True)
    run([cli,'--export','-u',key,'--export-name','HSM test','--export-email','test@example.com','-a','-o','public.asc'])
    run(['gpg','--batch','--import','public.asc'])
    (root/'input').write_bytes(b'HSM smoke test\n')
    run([cli,'-bsau',key,'--description',marker,'-o','input.asc','input'])
    run(['gpg','--verify','input.asc','input'])
subprocess.run([sys.executable,str(Path(__file__).with_name('gcp-audit.py')),marker,key],check=True)
