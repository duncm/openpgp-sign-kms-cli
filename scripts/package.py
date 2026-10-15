#!/usr/bin/env python3
"""Package the tested executable, sources, notices, inventory and checksums."""
import hashlib,json,pathlib,shutil,subprocess,sys,tarfile
root=pathlib.Path(__file__).resolve().parents[1]
target=sys.argv[1]
if target not in ['x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu']:raise SystemExit('unsupported target')
host=subprocess.check_output(['rustc','-vV'],text=True).split('host: ')[1].splitlines()[0]
if host!=target:raise SystemExit('target must match the native build host')
meta=json.loads(subprocess.check_output(['cargo','metadata','--locked','--format-version','1'],cwd=root))
version=next(p['version'] for p in meta['packages'] if p['id']==meta['resolve']['root'])
dist=root/'dist';dist.mkdir(exist_ok=True)
name=f'openpgp-sign-kms-{version}-{target}'
stage=root/'target'/'package'/name;stage.mkdir(parents=True,exist_ok=True)
for src,dst in [(root/'target/release/openpgp-sign-kms',stage/'openpgp-sign-kms'),(root/'LICENSE',stage/'LICENSE'),(root/'README.md',stage/'README.md')]:shutil.copy2(src,dst)
(stage/'THIRD-PARTY-NOTICES.txt').write_text('Sequoia OpenPGP is LGPL-2.0-or-later. OpenSSL is Apache-2.0. Other dependencies retain their licenses. Full notices and sources are in the corresponding source archive. See dependencies.json and the source rebuild guide.\n')
archive=dist/(name+'.tar.gz')
with tarfile.open(archive,'w:gz') as tar:
 for p in sorted(stage.iterdir()):tar.add(p,arcname=p.name)
packages=[{'name':p['name'],'version':p['version'],'license':p['license'],'source':p['source']} for p in meta['packages']]
(dist/f'dependencies-{target}.json').write_text(json.dumps(packages,indent=2)+'\n')
(dist/f'sbom-{target}.cdx.json').write_text(json.dumps({'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'components':[{'type':'library','name':p['name'],'version':p['version'],'purl':f"pkg:cargo/{p['name']}@{p['version']}"} for p in packages]},indent=2)+'\n')
if target.startswith('x86_64') or '--source' in sys.argv:
 source=root/'target'/'release-source';shutil.rmtree(source,ignore_errors=True);source.mkdir()
 tracked=subprocess.check_output(['git','ls-files','-z'],cwd=root).decode().split('\0')
 for name in filter(None,tracked):
  src=root/name;dst=source/name
  if src.is_file():dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
 config=subprocess.check_output(['cargo','vendor','--locked','--versioned-dirs',str(source/'vendor')],cwd=root).decode()
 (source/'.cargo').mkdir(exist_ok=True)
 (source/'.cargo/config.toml').write_text(config.replace(str(source/'vendor'),'vendor'))
 (source/'REBUILD.md').write_text('Install the Rust toolchain from rust-toolchain.toml and build prerequisites listed in docs/contributing.md. Run cargo build --release --locked --offline. All Cargo dependency sources and their license files are in vendor/. Changes to Sequoia can be rebuilt and relinked with the MIT application using this command.\n')
 with tarfile.open(dist/f'openpgp-sign-kms-{version}-source.tar.gz','w:gz') as tar:tar.add(source,arcname=f'openpgp-sign-kms-{version}-source')
with (dist/(target+'.sha256')).open('w') as out:
 for p in sorted(dist.iterdir()):
  if p.is_file() and not p.name.endswith('.sha256'):
   out.write(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n')
print(archive)
