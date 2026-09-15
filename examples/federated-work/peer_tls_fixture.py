"""Short-lived CA and server leaf for local peer transport qualification."""
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def create(state, host):
    now = datetime.now(timezone.utc)
    authority = ec.generate_private_key(ec.SECP256R1())
    leaf = ec.generate_private_key(ec.SECP256R1())
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Chio local peer test CA")])
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    try:
        san = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san = x509.DNSName(host)

    def builder(name, public):
        return (x509.CertificateBuilder().subject_name(name).issuer_name(issuer)
                .public_key(public).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(hours=2)))

    ca = (builder(issuer, authority.public_key())
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                      encipher_only=False, decipher_only=False), critical=True)
          .sign(authority, hashes.SHA256()))
    cert = (builder(subject, leaf.public_key())
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(authority, hashes.SHA256()))
    # The CA private key is never written; only the receiver has its TLS leaf key.
    for name, raw in (("root-cert.pem", ca.public_bytes(serialization.Encoding.PEM)),
                      ("tls-cert.pem", cert.public_bytes(serialization.Encoding.PEM)),
                      ("tls-key.pem", leaf.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.NoEncryption()))):
        with os.fdopen(os.open(Path(state) / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
