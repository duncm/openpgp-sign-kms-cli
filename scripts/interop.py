#!/usr/bin/env python3
"""Exercise the production OpenPGP and argument code with an explicitly test-only signer."""
import os, pathlib, subprocess, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
SIGNER = str(ROOT / 'target/debug/examples/offline-signer')
CLI = str(ROOT / 'target/debug/openpgp-sign-kms')
ARN = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'

def run(args, *, env, cwd, data=None, ok=True):
    p = subprocess.run(args, input=data, env=env, cwd=cwd, capture_output=True)
    if ok and p.returncode:
        raise AssertionError(f'{args!r}: {p.returncode}\n{p.stderr.decode(errors="replace")}')
    if not ok and not p.returncode:
        raise AssertionError(f'Unexpected success: {args!r}')
    return p

def main():
    for kind in ['RSA:2048', 'RSA:3072', 'RSA:4096', 'ED25519']:
        with tempfile.TemporaryDirectory(prefix='kms-interop-') as temp:
            work = pathlib.Path(temp)
            home = work / 'gnupg'; home.mkdir(mode=0o700)
            env = dict(os.environ, GNUPGHOME=str(home), TEST_SIGNING_PEM=str(work/'key.pem'), OPENPGP_SIGN_KMS_GPG='/usr/bin/gpg')
            def cmd(args, **kw): return run(args, env=env, cwd=work, **kw)
            gen = ['openssl', 'genpkey', '-algorithm', kind.split(':')[0], '-out', env['TEST_SIGNING_PEM']]
            if ':' in kind: gen += ['-pkeyopt', 'rsa_keygen_bits:'+kind.split(':')[1]]
            cmd(gen)
            export = [SIGNER, '--export', '-u', ARN, '--export-name', 'KMS Test', '--export-email', 'test@example.com', '-a']
            public = cmd(export).stdout
            cmd(['gpg', '--batch', '--import'], data=public)
            first = cmd(['gpg','--batch','--with-colons','--show-keys'], data=public).stdout
            second = cmd(['gpg','--batch','--with-colons','--show-keys'], data=cmd(export).stdout).stdout
            assert [l for l in first.splitlines() if l.startswith(b'fpr:')] == [l for l in second.splitlines() if l.startswith(b'fpr:')]
            inputs = [b'', b'hello\n', b'hello\r\n', b'one \t\n-two\t\nlast', b'no final newline', b'\x00\xff\x80binary\x00']
            inputs += [b'large payload\n' * 500000]
            for n, data in enumerate(inputs):
                source = work/'input'; source.write_bytes(data)
                for mode in ['sign','detach-sign','clear-sign']:
                    if mode=='clear-sign' and b'\xff' in data: continue
                    for armor in [False, True]:
                        output = work/'output'; output.unlink(missing_ok=True)
                        args=[SIGNER, '--'+mode, '-u', ARN, '--status-fd=2', '-o', str(output)]
                        if armor:args+=['-a']
                        result=cmd(args+[str(source)])
                        assert b'[GNUPG:] SIG_CREATED ' in result.stderr
                        verify=['gpg','--batch','--verify',str(output)]
                        if mode=='detach-sign':verify += [str(source)]
                        cmd(verify)
                        if mode=='sign':assert cmd(['gpg','--batch','--decrypt',str(output)]).stdout==data
                        if mode=='detach-sign':
                            source.write_bytes(data+b'changed');cmd(verify,ok=False);source.write_bytes(data)
                if n==0:
                    cmd([SIGNER,'-s','-u',ARN,'-o',str(source),str(source)],ok=False)
            # Real Git invokes -bsau and requires SIG_CREATED on stderr.
            cmd(['git','init','-q'])
            for key,val in [('user.name','KMS Test'),('user.email','test@example.com'),('user.signingkey',ARN),('gpg.program',SIGNER)]:cmd(['git','config',key,val])
            cmd(['git','add','input']);cmd(['git','commit','-S','-m','signed commit']);cmd(['git','tag','-s','v0.1-test','-m','signed tag'])
            cmd(['git','config','gpg.program',CLI])
            cmd(['git','verify-commit','HEAD']);cmd(['git','verify-tag','v0.1-test'])
            # These do not initialize AWS, even with no credentials.
            cmd([CLI,'--gpg-program','/bin/false','--verify','missing'],ok=False)
            cmd([CLI,'--gpg-program',CLI,'--verify','missing'],ok=False)
            cmd([CLI,'--verify','--sign'],ok=False)
            print(f'{kind}: export, formats, edge cases, Git signing and delegation passed',flush=True)
if __name__ == '__main__':main()
