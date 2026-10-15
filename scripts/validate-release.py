#!/usr/bin/env python3
import json,os,pathlib,re,subprocess
root=pathlib.Path(__file__).resolve().parents[1]
version=(json.loads(subprocess.check_output(['cargo','metadata','--no-deps','--format-version','1'],cwd=root))['packages'][0]['version'] if (root/'Cargo.toml').exists() else json.loads((root/'package.json').read_text())['version'])
tag=os.environ['GITHUB_REF_NAME']
if tag!='v'+version or not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?',tag):raise SystemExit('Tag must match package version')
subprocess.run(['git','fetch','origin','main'],check=True)
subprocess.run(['git','merge-base','--is-ancestor','HEAD','origin/main'],check=True)
print('Version and ancestry passed')
