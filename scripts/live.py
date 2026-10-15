#!/usr/bin/env python3
"""Verify real KMS signatures from the exact candidate executable."""
import hashlib,os,pathlib,subprocess,sys,tempfile,uuid
binary=str(pathlib.Path(sys.argv[1]).resolve())
description='integration-'+str(uuid.uuid4())
for variable in ['KMS_RSA_KEY_ARN','KMS_ED25519_KEY_ARN']:
 key=os.environ[variable]
 if not key:raise SystemExit(variable+' is required')
 with tempfile.TemporaryDirectory() as temp:
  root=pathlib.Path(temp);home=root/'gnupg';home.mkdir(mode=0o700)
  env=dict(os.environ,GNUPGHOME=str(home))
  def run(args):subprocess.run(args,cwd=root,env=env,check=True)
  (root/'input').write_bytes(b'Live KMS test\n- second line\n')
  run([binary,'--export','-u',key,'--export-name','Integration','--export-email','test@example.com','-a','-o','public.asc'])
  run(['gpg','--batch','--import','public.asc'])
  for mode in ['sign','detach-sign','clear-sign']:
   for armor in [False,True]:
    output=mode+str(armor)
    args=[binary,'--'+mode,'-u',key,'--description',description,'-o',output]
    if armor:args.append('-a')
    run(args+['input'])
    run(['gpg','--batch','--verify',output]+(['input'] if mode=='detach-sign' else []))
    if mode=='sign':
     result=subprocess.run(['gpg','--batch','--decrypt',output],cwd=root,env=env,check=True,capture_output=True)
     assert result.stdout==(root/'input').read_bytes()
  # Opt-in enrichment through actual Git invocations, using the same exported cert.
  env['OPENPGP_SIGN_KMS_GPG']='/usr/bin/gpg'
  env['OPENPGP_SIGN_KMS_GIT_METADATA']='auto'
  env['OPENPGP_SIGN_KMS_DESCRIPTION']=description
  run(['git','init','-q'])
  for name,value in [('user.name','Integration'),('user.email','test@example.com'),('user.signingkey',key),('gpg.program',binary)]:
   run(['git','config',name,value])
  run(['git','add','input']);run(['git','commit','-S','-m','Live signed commit'])
  run(['git','tag','-s','integration','-m','Live signed tag'])
  run(['git','verify-commit','HEAD']);run(['git','verify-tag','integration'])
  payload=('object '+'a'*40+'\ntype commit\ntag integration\n\nAudit enrichment test').encode()
  (root/'git-payload').write_bytes(payload)
  run([binary,'-bsau',key,'-o','git.sig','git-payload'])
  run(['gpg','--batch','--verify','git.sig','git-payload'])
  enriched=description+'\ngit_type=tag payload_sha256='+hashlib.sha256(payload).hexdigest()+' target_id='+'a'*40+' target_type=commit tag=integration'
for marker in [description,enriched]:
 subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('cloudtrail.py')),marker],check=True)
