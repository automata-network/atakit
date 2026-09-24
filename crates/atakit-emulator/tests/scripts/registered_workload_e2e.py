#!/usr/bin/env python3
"""Run secure-signer against an existing Emulator and its business verifier on B."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--runtime', required=True)
parser.add_argument('--app', required=True)
parser.add_argument('--verifier', required=True)
parser.add_argument('--workload')
args = parser.parse_args()
root = Path(args.runtime)

def endpoints():
    return json.loads((root / 'endpoints.json').read_text())

initial = endpoints()
name = args.workload or next(iter(initial['workloads']))
assert args.workload or len(initial['workloads']) == 1
info = initial['workloads'][name]
assert initial['state'] == 'ready'
assert initial['rpc_url'].startswith('http://127.0.0.1:')

def rpc(url, method, params):
    request = urllib.request.Request(url, json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params,
    }).encode(), {'Content-Type': 'application/json'})
    value = json.load(urllib.request.urlopen(request, timeout=30))
    assert 'error' not in value, value
    return value['result']

upstream_block = rpc(initial['upstream_rpc_url'], 'eth_blockNumber', [])

def control(operation):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(180)
        stream.connect(str(root / 'control.sock'))
        stream.sendall((json.dumps({
            'environment_id': initial['environment_id'],
            'operation': operation, 'workload': name,
        }) + '\n').encode())
        value = json.loads(stream.makefile().readline())
        assert 'error' not in value, value
        return value

def http(route, body=None):
    request = urllib.request.Request(base + route, body, {'Content-Type': 'text/plain'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()

def verify(signed, message, owner=None, workload=None, rejection=None):
    key = signed['session_pubkey']
    result = subprocess.run([
        'cast', 'call', args.verifier,
        'verifyPortalMessage(bytes32,(uint8,bytes),bytes,bytes,bytes32,bytes32)(bool)',
        signed['session_id'], f"({key['type_id']},{key['key']})", '0x' + message.hex(),
        signed['signature'], owner or info['owner_fingerprint'],
        workload or info['workload_id'], '--rpc-url', initial['rpc_url'],
    ], capture_output=True, text=True)
    if rejection:
        assert result.returncode != 0 and 'execution reverted' in result.stderr, result.stderr
        assert rejection in result.stderr, result.stderr
    else:
        assert result.returncode == 0 and result.stdout.strip() == 'true', result.stderr

with socket.socket() as reservation:
    reservation.bind(('127.0.0.1', 0))
    port = reservation.getsockname()[1]
base = f'http://127.0.0.1:{port}'
env = {**os.environ, **info['env'], 'SIGNATURE_VERIFIER': args.verifier,
       'VERIFY_ON_CHAIN': 'true', 'LISTEN_ADDR': f'127.0.0.1:{port}'}
with (root / 'business-e2e.log').open('ab') as log:
    process = subprocess.Popen([args.app], env=env, stdout=log, stderr=log)
try:
    for _ in range(100):
        assert process.poll() is None, 'application exited; inspect business-e2e.log'
        try:
            if http('/')[0] == 200:
                break
        except OSError:
            pass
        time.sleep(.05)
    else:
        raise AssertionError('application readiness timeout')
    message = b'hoodi-native-emulator'
    status, body = http('/sign-message', message)
    assert status == 200, (status, body)
    signed = json.loads(body)
    verify(signed, message)
    verify(signed, message + b'-wrong', rejection='0x8baa579f')  # InvalidSignature()
    verify(signed, message, owner='0x' + '00' * 32, rejection='0xa8c81623')
    verify(signed, message, workload='0x' + '00' * 32, rejection='0x31fbd24e')
    control('rotate')
    status, body = http('/sign-message', b'after-rotate')
    assert status == 200, (status, body)
    rotated = json.loads(body)
    assert rotated['session_id'] != signed['session_id']
    verify(rotated, b'after-rotate')
    control('revoke')
    assert http('/sign-message', b'after-revoke')[0] == 503
    result = subprocess.run(['cast', 'call', initial['session_registry'],
        'isSessionActive(bytes32)(bool)', rotated['session_id'], '--rpc-url', initial['rpc_url']],
        capture_output=True, text=True)
    assert result.returncode == 0 and result.stdout.strip() == 'false', result.stderr
    assert rpc(initial['upstream_rpc_url'], 'eth_blockNumber', []) == upstream_block
    print('PASS: current workload, native HTTP -> business contract -> real Registry, wrong message/owner/workload rejected, rotate/revoke, upstream unchanged')
finally:
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
