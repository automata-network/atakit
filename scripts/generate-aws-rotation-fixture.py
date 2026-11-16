#!/usr/bin/env python3
"""Generate synthetic rotation evidence. Requires cryptography, cbor2, pycryptodome.

Run from the repository root. All signing keys are generated in memory and
never saved. This fixture does not claim AMD hardware authentication.
"""
import base64
import datetime
import hashlib
import json
import struct
from pathlib import Path

import cbor2
from Crypto.Hash import keccak
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID


def b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


def hx(b):
    return '0x' + b.hex()


def k256(b):
    return keccak.new(digest_bits=256, data=b).digest()


def word(n):
    return n.to_bytes(32, 'big')


def fingerprint(key):
    return k256(k256(b'KEY_RESOLVER_V1') + word(2) + word(96) + word(len(key)) + key + bytes((-len(key)) % 32))


def certificate(key, name, issuer_key=None, issuer=None, ca=False):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (x509.CertificateBuilder().subject_name(subject)
            .issuer_name(issuer.subject if issuer else subject)
            .public_key(key.public_key()).serial_number(1 if ca else 2)
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, ca, ca, None, None), critical=True)
            .sign(issuer_key or key, hashes.SHA384()))


def raw_signature(key, message, algorithm, size):
    r, s = utils.decode_dss_signature(key.sign(message, ec.ECDSA(algorithm)))
    return r.to_bytes(size, 'big') + s.to_bytes(size, 'big')


def main():
    ak = ec.generate_private_key(ec.SECP256R1())
    root_key = ec.generate_private_key(ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    root = certificate(root_key, 'Synthetic Nitro test root', ca=True)
    leaf = certificate(leaf_key, 'Synthetic Nitro test leaf', root_key, root)
    public = ak.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    ak_public = bytes.fromhex('0023000b00060072000000100018000b00030010') + struct.pack('>H',32) + public[1:33] + struct.pack('>H',32) + public[33:]
    fp = fingerprint(public)
    report_id = bytes([0x42])*32
    pcrs = {i: bytes([i])*48 for i in range(24)}
    pcrs[15] = hashlib.sha384(bytes(64)+report_id).digest()
    selected = [0,15]
    select = bytes([1,128,0])
    digest = hashlib.sha256(b''.join(pcrs[i] for i in selected)).digest()
    pcr_select = bytes.fromhex('000c') + select + bytes(27)
    report = bytearray(1184)
    report[0:4] = (3).to_bytes(4,'little')
    report[0x50:0x70] = fp
    report[0x70:0x90] = k256(k256(b'CVM_AWS_REPORT_DATA_PCR_COMMITMENT_V1')+pcr_select+digest)
    report[0x140:0x160] = report_id
    nonce = bytes([0x21])*32
    payload = cbor2.dumps({'module_id':'synthetic-module','digest':'SHA384','timestamp':1700000000000,
        'certificate':leaf.public_bytes(serialization.Encoding.DER),
        'cabundle':[root.public_bytes(serialization.Encoding.DER)],
        'public_key':ak.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo),
        'nonce':nonce,'nitrotpm_pcrs':pcrs})
    protected=bytes.fromhex('a1013822')
    signature=raw_signature(leaf_key,cbor2.dumps(['Signature1',protected,b'',payload]),hashes.SHA384(),48)
    document=cbor2.dumps([protected,{},payload,signature])

    def quote(n):
        body=bytes.fromhex('ff5443478018')+bytes(2)+struct.pack('>H',32)+n+bytes(25)+struct.pack('>I',1)+bytes.fromhex('000c03')+select+struct.pack('>H',32)+digest
        sig=raw_signature(ak,body,hashes.SHA256(),32)
        tpm_sig=bytes.fromhex('0018000b0020')+sig[:32]+bytes.fromhex('0020')+sig[32:]
        return {'tpms_attest':b64(struct.pack('>H',len(body))+body),'tpm_signature':b64(tpm_sig),'signature_hash':hx(k256(tpm_sig)),'pcr0_startup_locality':0}

    def binding(n):
        return {'mode':'local','chain_id':0,'registry':hx(bytes(20)),'owner_nonce':hx(n),'qualifying_data':hx(n)}
    probe={'attempted':False,'matched':False,'http_status':None,'response_headers':{},'response_body':None,'error':None}
    provenance={'source':'dmi','user_provided':None,'detection':{'dmi':{'sys_vendor':None,'product_name':None,'bios_vendor':None,'detected_cloud':'aws'},'metadata':{'gcp':probe,'azure':probe,'aws':probe,'detected_cloud':'unknown','conflict':False}}}
    key={'type_id':2,'bytes':hx(public),'fingerprint':hx(fp)}
    certify={'tpms_attest':'','tpm_signature':'','tpmt_public':b64(ak_public)}
    policy={name:hx(bytes([i])*32) for i,name in enumerate(['workload_id','base_image_id','platform_profile_id','measurement_variant_id'],1)}
    policy['pcr_bank_selection']='sha384'
    for name in ['invariant_pcr_policy','variant_pcr_policy','workload_pcr_policy','provider_pcr_policy']:
        policy[name]={'pcr_specs256':[],'pcr_specs384':[]}
    values=[{'index':i,'sha256':None,'sha384':hx(pcrs[i])} for i in selected]
    events=[{'pcr_index':i,'sha256':[],'sha384':[]} for i in selected]
    bundle={'format':2,'binding':binding(bytes([0x22])*32),'platform':{'cloud':'aws','tee':'sev-snp','machine_type':'m6a.large','attestation_mode':'hardware','cloud_provenance':provenance},
        'tee_evidence':{'kind':'configfs_tsm','report':b64(report),'auxiliary':None},
        'ak_evidence':{'kind':'aws_nitro_doc','ak_public':b64(ak_public),'collateral':b64(document)},
        'tpm_quote':quote(bytes([0x22])*32),'tpm_certify':certify,'pcr_values':values,'event_log_hashes':events,
        'session_key':key,'session_key_delegation':{'tpm_signing_key':key,'digest':hx(bytes(32)),'signature':'0x','session_key_possession_signature':'0x'},
        'session_id':hx(bytes([0x33])*32),'policy':policy,'owner':{'fingerprint':hx(bytes([0x11])*32),'contract_authorization':None},
        'provider_binding':{'binding':binding(nonce),'tpm_quote':quote(nonce),'tpm_certify':certify,'pcr_values':values,'event_log_hashes':events,'tpm_signing_key':key,'session_id':hx(bytes([0x34])*32),'policy':policy}}
    path=Path('crates/atakit-attestation/testdata/aws-rotation/evidence.json')
    path.write_text(json.dumps({'evidence_bundle':bundle},indent=2)+'\n')
    print('Generated synthetic AWS rotation fixture; no private keys saved.')


if __name__=='__main__':
    main()
