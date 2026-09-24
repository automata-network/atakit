#!/usr/bin/env python3
"""Exercise an already-running local emulator with the secure-signer native binary.
No public-chain writes. Requires two named instances and configured business verifier.
"""
import argparse,json,pathlib,subprocess,urllib.request,urllib.error,socket,time,os
p=argparse.ArgumentParser();p.add_argument('--runtime',required=True);p.add_argument('--app',required=True);p.add_argument('--lifecycle',action='store_true');a=p.parse_args()
root=pathlib.Path(a.runtime);apps=[]
def endpoints():return json.loads((root/'endpoints.json').read_text())
def control(operation,name=None):
    s=socket.socket(socket.AF_UNIX);s.settimeout(180);s.connect(str(root/'control.sock'))
    s.sendall((json.dumps({'environment_id':endpoints()['environment_id'],'operation':operation,'workload':name})+'\n').encode())
    value=json.loads(s.makefile().readline());s.close();assert 'error' not in value,value;return value
def http(url,body=None):
    req=urllib.request.Request(url,body,{'Content-Type':'text/plain'})
    try:
        with urllib.request.urlopen(req,timeout=15) as response:return response.status,response.read()
    except urllib.error.HTTPError as e:return e.code,e.read()
def start(name):
    info=endpoints()['workloads'][name]
    env={**os.environ,**info['env']}
    sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close()
    env['LISTEN_ADDR']=f'127.0.0.1:{port}';log=open(root/f'{name}-app.log','ab')
    proc=subprocess.Popen([a.app],env=env,stdout=log,stderr=log);apps.append(proc);base=f'http://127.0.0.1:{port}'
    for _ in range(100):
        assert proc.poll() is None,(root/f'{name}-app.log').read_text()
        try:
            if http(base+'/')[0]==200:return proc,base
        except OSError:pass
        time.sleep(.05)
    raise AssertionError('app startup timeout')
try:
    names=list(endpoints()['workloads']);assert len(names)>=2
    first,second=names[:2];proc,url=start(first);_,url2=start(second)
    assert http(url+'/')[0]==200
    assert http(url+'/signer_key')[1]==b'public-emulator-fixture'
    assert http(url+'/write_data',b'local-persistence')[0]==200
    assert http(url+'/read_data')[1]==b'local-persistence'
    code,body=http(url+'/sign-message',b'hello-emulator');assert code==200,(code,body)
    signed=json.loads(body);sid=signed['session_id'];assert sid==endpoints()['workloads'][first]['session_id']
    assert http(url2+'/sign-message',b'second')[0]==200
    assert http(url+'/platform')[0]==200
    proc.terminate();proc.wait(timeout=10);proc,url=start(first)
    assert json.loads(http(url+'/sign-message',b'after-app-restart')[1])['session_id']==sid
    assert http(url+'/read_data')[1]==b'local-persistence'
    if a.lifecycle:
        other=endpoints()['workloads'][second]['session_id'];control('rotate',first)
        rotated=endpoints()['workloads'][first]['session_id'];assert rotated!=sid
        assert endpoints()['workloads'][second]['session_id']==other
        assert json.loads(http(url+'/sign-message',b'after-rotate')[1])['session_id']==rotated
        control('revoke',first);assert http(url+'/sign-message',b'revoked')[0]==503
        assert http(url2+'/sign-message',b'other-still-active')[0]==200
        control('refresh');assert endpoints()['state']=='ready'
        assert json.loads(http(url+'/sign-message',b'after-refresh')[1])['session_id'] not in [sid,rotated]
    print('PASS: two native applications, data read/write, real business-contract verification, app restart'+(', rotate/revoke/refresh isolation' if a.lifecycle else ''))
finally:
    for proc in apps:
        if proc.poll() is None:proc.terminate()
    for proc in apps:
        try:proc.wait(timeout=10)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
