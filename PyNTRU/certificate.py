from PyNTRU.ntru.NTRU import *
from PyNTRU.sign import *
from PyNTRU.keys import *
from PyNTRU.ntru.hash import *
import datetime

#information signed with a certifying authority key used to verify the document
def request(version, subject_name, subjectPKInfo, issuerPK, signature):
    request = f"version: {version}\nsubject name: {subject_name}\nsubject public key: {subjectPKInfo}"
    request_hash = create_hash(request)
    m, s = signature.sign(issuerPK, request_hash)
    
    return m, s

#creates a x509 certificate
def create_certificate(issuer_name, sub_name, sub_pubkey, id, local, request):
    filename = f"{local}certificate_{id}.pem"
    with open(filename, "w") as cert:
        current_time = datetime.datetime.now()
        cert.write(f'Certificate:\n')
        cert.write(f'    Data:\n')
        cert.write(f'       Version:\n')
        cert.write(f'       Serial number:\n')
        cert.write(f'       Signature Algorithm: sha256WithNTRUEncryption\n')
        cert.write(f'       Issuer: C=BR, O={issuer_name}\n')
        cert.write(f'       Validity:\n')
        cert.write(f'           Not Before: {current_time.month} {current_time.day} {current_time.hour}:{current_time.minute}:{current_time.second} {current_time.year}\n')
        cert.write(f'           Not After: {current_time.month} {current_time.day} {current_time.hour}:{current_time.minute}:{current_time.second} {current_time.year+1}\n')
        cert.write(f'       Subject: C=BR, ST=MG, O={sub_name}\n')
        cert.write(f'       Subject Public Key Info:\n')
        cert.write(f'           Public key algorithm: NTRU\n')
        cert.write(f'           Public key: (2048 bit)\n')
        cert.write(f'           Pub:\n')
        cert.write(f'               {sub_pubkey}\n')
        cert.write(f'    Signature Algorithm: sha256WithNTRUEncryption\n')
        cert.write(f'        {request}\n') 

#extracts public key fromm x509 certificate
def get_pub_key(certificate_file):
    with open(certificate_file, 'r') as file:
        text = file.read() 
        text = text.split("Pub:\n               ")
        text = text[1].split("Signature")
        return import_key(text[0])

