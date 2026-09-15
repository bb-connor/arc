"""Generate a private, short-lived TLS fixture inside the provider namespace.

Operator deployments supply their own certificate, key and trust chain.
This utility creates no application identity or enrollment credential.
"""
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def create(state, host):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Chio test provider")])
    try:
        san = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san = x509.DNSName(host)
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
                   .not_valid_after(now + timedelta(hours=2))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                               key_encipherment=False, data_encipherment=False, key_agreement=False,
                                               key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
                   .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
                   .sign(key, hashes.SHA256()))
    for name, data in (("tls-cert.pem", certificate.public_bytes(serialization.Encoding.PEM)),
                       ("tls-key.pem", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))):
        fd = os.open(Path(state) / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    print('{"created":true}')


if __name__ == "__main__":
    os.umask(0o077)
    create(*sys.argv[1:])
