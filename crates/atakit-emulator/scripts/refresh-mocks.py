#!/usr/bin/env python3
"""Rebuild embedded stateless hardware mocks from the companion contract checkout."""
import argparse,hashlib,json,pathlib,subprocess
p=argparse.ArgumentParser();p.add_argument('--contracts',type=pathlib.Path,required=True);args=p.parse_args()
subprocess.run(['forge','build','--offline'],cwd=args.contracts,check=True)
assets=pathlib.Path(__file__).resolve().parents[1]/'assets';manifest={}
for name in ['EmulatorDcapAttestation','EmulatorTpmAttestation']:
    source=args.contracts/'test/mocks'/f'{name}.sol'
    artifact=json.loads((args.contracts/'out'/f'{name}.sol'/f'{name}.json').read_text())
    deployed=artifact['deployedBytecode'];assert not deployed.get('immutableReferences'), 'mock must be stateless with no linked immutables'
    code=deployed['object'].removeprefix('0x');bytes.fromhex(code)
    (assets/f'{name}.runtime.hex').write_text(code+'\n')
    manifest[name]={'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'runtime_sha256':hashlib.sha256(bytes.fromhex(code)).hexdigest()}
(assets/'mocks-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
