#!/usr/bin/env python3
"""Production SDK integration against a local KMS protocol server. No real AWS access."""
import base64,http.server,json,os,pathlib,subprocess,tempfile,threading
ROOT=pathlib.Path(__file__).resolve().parents[1]
CLI=str(ROOT/'target/debug/openpgp-sign-kms')
VERSION=subprocess.check_output([CLI,'--version']).decode().split()[-1]
ARN='arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
class Server(http.server.ThreadingHTTPServer):
    allow_reuse_address=True
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_POST(self):
        s=self.server
        data=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        op=self.headers['X-Amz-Target'].split('.')[-1]
        s.calls.append((op,data,self.headers.get('User-Agent','')))
        result={};status=200
        if op=='DescribeKey':
            result={'KeyMetadata':{'AWSAccountId':'123456789012','KeyId':ARN.split('/')[-1],'Arn':ARN,'CreationDate':1700000000,'Enabled':not s.disabled,'KeyState':'Disabled' if s.disabled else 'Enabled','KeyUsage':'SIGN_VERIFY','KeySpec':s.spec}}
        elif op=='GetPublicKey':
            result={'KeyId':ARN,'PublicKey':base64.b64encode(s.der).decode(),'KeySpec':s.spec,'KeyUsage':'SIGN_VERIFY','SigningAlgorithms':(['ED25519_SHA_512'] if s.spec.startswith('ECC') else ['RSASSA_PKCS1_V1_5_SHA_256','RSASSA_PKCS1_V1_5_SHA_384','RSASSA_PKCS1_V1_5_SHA_512'])}
        elif op=='Sign':
            s.attempts+=1
            if s.attempts<=s.failures:
                status=503;result={'__type':'KMSInternalException','message':'retry test'}
            else:
                assert data['KeyId']==ARN
                assert data['MessageType']==('RAW' if s.spec.startswith('ECC') else 'DIGEST')
                assert data['SigningAlgorithm']==s.algorithm
                digest=base64.b64decode(data['Message'])
                source=s.root/'digest';source.write_bytes(digest)
                args=['openssl','pkeyutl','-sign','-inkey',str(s.root/'key.pem'),'-in',str(source)]
                if s.spec.startswith('ECC'):args+=['-rawin']
                else:args+=['-pkeyopt','rsa_padding_mode:pkcs1','-pkeyopt','digest:sha'+s.algorithm.split('_')[-1]]
                signature=subprocess.check_output(args)
                if s.corrupt:signature=bytes([signature[0]^1])+signature[1:]
                result={'KeyId':ARN,'SigningAlgorithm':s.algorithm,'Signature':base64.b64encode(signature).decode()}
        else:raise AssertionError(op)
        body=json.dumps(result).encode();self.send_response(status);self.send_header('Content-Type','application/x-amz-json-1.1');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)

def main():
 for spec in ['RSA_2048','ECC_NIST_EDWARDS25519']:
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp)
   args=['openssl','genpkey','-algorithm','ED25519' if spec.startswith('ECC') else 'RSA','-out',str(root/'key.pem')]
   if spec=='RSA_2048':args+=['-pkeyopt','rsa_keygen_bits:2048']
   subprocess.run(args,check=True,capture_output=True)
   der=subprocess.check_output(['openssl','pkey','-in',str(root/'key.pem'),'-pubout','-outform','DER'])
   server=Server(('127.0.0.1',0),Handler);server.root=root;server.der=der;server.spec=spec
   server.algorithm='ED25519_SHA_512' if spec.startswith('ECC') else 'RSASSA_PKCS1_V1_5_SHA_256'
   thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
   env=dict(os.environ,AWS_ACCESS_KEY_ID='test',AWS_SECRET_ACCESS_KEY='test',AWS_EC2_METADATA_DISABLED='true',AWS_ENDPOINT_URL_KMS=f'http://127.0.0.1:{server.server_port}')
   env.pop('AWS_SESSION_TOKEN',None)
   try:
    for scenario in (['success','disabled','corrupt','retry','denied','bad-status','long-description']+(['sha384','sha512'] if spec=='RSA_2048' else [])):
     server.calls=[];server.attempts=0;server.failures=2 if scenario=='retry' else 99 if scenario=='denied' else 0;server.corrupt=scenario=='corrupt';server.disabled=scenario=='disabled'
     server.algorithm='ED25519_SHA_512' if spec.startswith('ECC') else 'RSASSA_PKCS1_V1_5_SHA_'+(scenario[3:] if scenario.startswith('sha') else '256')
     output=root/'out';output.unlink(missing_ok=True)
     args=[CLI,'-bsau',ARN,'-o',str(output),'--description','sdk test ✓' if scenario!='long-description' else 'x'*2000]
     if scenario.startswith('sha'):args+=['--digest-algo',scenario]
     args+=['--status-fd', '99999' if scenario=='bad-status' else '2']
     result=subprocess.run(args,input=b'sdk test\n',env=env,capture_output=True)
     success=scenario in ['success','retry','sha384','sha512']
     assert (result.returncode==0)==success,(scenario,result.stderr)
     assert output.exists()==success,(scenario,'output publication')
     assert (b'[GNUPG:] SIG_CREATED ' in result.stderr)==success
     expected=3 if scenario in ['retry','denied'] else 0 if scenario in ['disabled','bad-status','long-description'] else 1
     assert server.attempts==expected,(scenario,server.attempts)
     for op,data,ua in server.calls:
      if op=='Sign':
       assert ua=='openpgp-sign-kms/'+VERSION+' description/'+base64.urlsafe_b64encode('sdk test ✓'.encode()).decode().rstrip('='),ua
     if scenario=='success':
      # Refusal happens before any additional AWS operations.
      n=len(server.calls);again=subprocess.run(args,input=b'data',env=env,capture_output=True)
      assert again.returncode and len(server.calls)==n
     print(f'{spec}: SDK {scenario} passed',flush=True)
   finally:server.shutdown();server.server_close();thread.join()
if __name__=='__main__':main()
