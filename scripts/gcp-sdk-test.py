#!/usr/bin/env python3
"""Exercise the actual Google SDK wire protocol, retries and OpenPGP with no cloud access."""
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
CLI = str(ROOT / 'target/debug/examples/gcp-protocol-signer')
NAME = 'projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1'

def crc(data):
    value = 0xffffffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
    return value ^ 0xffffffff

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, body, status=200):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        s = self.server
        assert self.path.startswith('/v1/' + NAME), self.path
        if 'publicKey' in self.path:
            result = {'name': NAME, 'algorithm': s.algorithm, 'protectionLevel': s.protection,
                'pem': s.pem, 'pemCrc32c': str(crc(s.pem.encode()))}
            if s.scenario == 'public-crc':
                result['pemCrc32c'] = '0'
            if s.scenario == 'missing-crc':
                del result['pemCrc32c']
            if s.scenario == 'wrong-public-key':
                result['name'] += '2'
            if s.scenario == 'metadata-algorithm':
                result['algorithm'] = 'RSA_SIGN_PSS_2048_SHA256'
        else:
            result = {'name': NAME, 'algorithm': s.algorithm, 'state': 'ENABLED',
                'protectionLevel': s.protection, 'createTime': '2023-11-14T22:13:20.123456Z'}
            if s.scenario == 'disabled':
                result['state'] = 'DISABLED'
            if s.scenario == 'unsupported':
                result['algorithm'] = 'RSA_SIGN_PSS_2048_SHA256'
            if s.scenario == 'missing-created':
                del result['createTime']
            if s.scenario == 'wrong-version':
                result['name'] += '2'
            if s.scenario == 'external':
                result['protectionLevel'] = 'EXTERNAL'
        self.respond(result)

    def do_POST(self):
        s = self.server
        assert self.path.split('?', 1)[0] == '/v1/' + NAME + ':asymmetricSign', self.path
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        s.calls.append((request, self.headers['User-Agent']))
        if s.scenario == 'timeout':
            time.sleep(65)
        if s.scenario == 'denied':
            return self.respond({'error': {'code': 403, 'status': 'PERMISSION_DENIED', 'message': 'test denial'}}, 403)
        if s.scenario == 'exhausted' or (s.scenario == 'retry' and len(s.calls) < 3):
            return self.respond({'error': {'code': 503, 'status': 'UNAVAILABLE', 'message': 'test retry'}}, 503)
        ed = s.algorithm == 'EC_SIGN_ED25519'
        hash_name = 'sha512' if s.algorithm.endswith('SHA512') else 'sha256'
        digest = base64.b64decode(request['data'] if ed else request['digest'][hash_name])
        assert int(request['dataCrc32c' if ed else 'digestCrc32c']) == crc(digest)
        assert len(digest) == (64 if ed or hash_name == 'sha512' else 32)
        assert ('digest' not in request) if ed else ('data' not in request)
        source = s.root / 'digest'; source.write_bytes(digest)
        args = ['openssl', 'pkeyutl', '-sign', '-inkey', str(s.root / 'key.pem'), '-in', str(source)]
        args += ['-rawin'] if ed else ['-pkeyopt', 'rsa_padding_mode:pkcs1', '-pkeyopt', 'digest:' + hash_name]
        signature = subprocess.check_output(args)
        if s.scenario == 'corrupt':
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        result = {'name': NAME, 'signature': base64.b64encode(signature).decode(),
            'signatureCrc32c': str(crc(signature)), 'protectionLevel': s.protection,
            'verifiedDataCrc32c' if ed else 'verifiedDigestCrc32c': s.scenario != 'unverified-request'}
        if s.scenario == 'signature-crc':
            result['signatureCrc32c'] = '-1'
        if s.scenario == 'wrong-signing-key':
            result['name'] += '2'
        if s.scenario == 'wrong-protection':
            result['protectionLevel'] = 'EXTERNAL'
        self.respond(result)


def main():
    algorithms = ['RSA_SIGN_PKCS1_2048_SHA256', 'RSA_SIGN_PKCS1_3072_SHA256', 'RSA_SIGN_PKCS1_4096_SHA256', 'RSA_SIGN_PKCS1_4096_SHA512', 'EC_SIGN_ED25519']
    for algorithm in algorithms:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ed = algorithm == 'EC_SIGN_ED25519'
            command = ['openssl', 'genpkey', '-algorithm', 'ED25519' if ed else 'RSA', '-out', str(root / 'key.pem')]
            if not ed:
                command += ['-pkeyopt', 'rsa_keygen_bits:' + algorithm.split('_')[3]]
            subprocess.run(command, check=True, capture_output=True)
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.root = root
            server.algorithm = algorithm
            server.protection = 'SOFTWARE'
            server.pem = subprocess.check_output(['openssl', 'pkey', '-in', str(root / 'key.pem'), '-pubout'], text=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            env = dict(os.environ, TEST_GOOGLE_ENDPOINT=f'http://127.0.0.1:{server.server_port}')
            scenarios = ['success', 'digest-mismatch', 'git-auto']
            if algorithm in (algorithms[0], algorithms[-1]):
                scenarios += ['disabled', 'unsupported', 'external', 'missing-created', 'wrong-version', 'public-crc', 'missing-crc', 'wrong-public-key', 'metadata-algorithm', 'signature-crc', 'unverified-request', 'corrupt', 'wrong-signing-key', 'wrong-protection', 'retry', 'exhausted', 'denied', 'long-description', 'budget']
            if not ed:
                scenarios += ['hsm']
            if algorithm == algorithms[0]:
                scenarios += ['timeout']
            try:
                for scenario in scenarios:
                    server.calls = []; server.scenario = scenario
                    server.protection = 'HSM' if scenario == 'hsm' else 'SOFTWARE'
                    out = root / 'out'; out.unlink(missing_ok=True)
                    description = 'sdk Google ✓' if scenario not in ['budget','long-description'] else 'x' * (740 if scenario == 'budget' else 1024)
                    args = [CLI, '-bsau', NAME, '-o', str(out), '--description', description, '--status-fd', '2']
                    payload = b'Google SDK protocol test\n'
                    if scenario == 'digest-mismatch':
                        args += ['--digest-algo', 'SHA384']
                    if scenario == 'git-auto':
                        payload = ('object ' + 'a'*40 + '\ntype commit\ntag sdk/test\n\nPrivate message').encode()
                        args += ['--git-metadata', 'auto']
                        description += '\ngit_type=tag payload_sha256=' + hashlib.sha256(payload).hexdigest() + ' target_id=' + 'a'*40 + ' target_type=commit tag=sdk%2Ftest'
                    started = time.monotonic()
                    result = subprocess.run(args, input=payload, env=env, capture_output=True, timeout=75)
                    success = scenario in ['success', 'retry', 'hsm', 'git-auto', 'budget']
                    assert (result.returncode == 0) == success, (algorithm, scenario, result.stderr)
                    assert out.exists() == success
                    assert (b'SIG_CREATED ' in result.stderr) == success
                    expected = 3 if scenario in ['retry', 'exhausted'] else 0 if scenario in ['disabled','unsupported','external','missing-created','wrong-version','public-crc','missing-crc','wrong-public-key','metadata-algorithm','digest-mismatch','long-description'] else 1
                    assert len(server.calls) == expected, (scenario, len(server.calls))
                    if scenario == 'timeout':
                        assert 55 <= time.monotonic() - started < 75
                    for request, ua in server.calls:
                        assert len(ua.encode()) <= 1024
                        assert ua.split(' description/')[1] == base64.urlsafe_b64encode(description.encode()).decode().rstrip('=')
                    if scenario == 'success':
                        home = root / 'gnupg'; home.mkdir(mode=0o700)
                        env['GNUPGHOME'] = str(home)
                        certs = []
                        for i in range(2):
                            certificate = root / f'public{i}.asc'
                            subprocess.run([CLI, '--export', '-u', NAME, '--export-name', 'Test', '--export-email', 'test@example.com', '-a', '-o', str(certificate)], env=env, check=True, capture_output=True)
                            certs.append(subprocess.check_output(['gpg','--batch','--with-colons','--show-keys', str(certificate)], env=env).decode().split('fpr:')[1].splitlines()[0])
                        assert certs[0] == certs[1]
                        subprocess.run(['gpg','--batch','--import', str(root/'public0.asc')], env=env, check=True, capture_output=True)
                        (root/'input').write_bytes(payload)
                        subprocess.run(['gpg','--verify',str(out),str(root/'input')],env=env,check=True,capture_output=True)
                        for mode in ['sign', 'detach-sign', 'clear-sign']:
                            for armored in [False, True]:
                                target = root / (mode + str(armored))
                                before = len(server.calls)
                                command = [CLI, '--' + mode, '-u', NAME, '-o', str(target)]
                                if armored: command.append('-a')
                                subprocess.run(command + [str(root/'input')], env=env, check=True, capture_output=True)
                                assert len(server.calls) == before + 1
                                subprocess.run(['gpg','--verify',str(target)] + ([str(root/'input')] if mode=='detach-sign' else []), env=env, check=True, capture_output=True)
                                if mode == 'sign':
                                    assert subprocess.check_output(['gpg','--batch','--decrypt',str(target)],env=env,stderr=subprocess.DEVNULL) == payload
                    print(algorithm + ': Google SDK ' + scenario + ' passed', flush=True)
            finally:
                server.shutdown(); server.server_close(); thread.join()

if __name__ == '__main__':
    main()
