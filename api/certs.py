"""
Certificate chain generation for SCITT signing.
Generates a self-signed CA and end-entity certificate on startup.
"""

import datetime
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@dataclass
class CertificateChain:
    """Holds the generated certificate chain and private key."""
    root_cert_pem: str
    leaf_cert_pem: str
    leaf_key_pem: str
    
    @property
    def chain_pem(self) -> str:
        """Return the full certificate chain (leaf + root)."""
        return self.leaf_cert_pem + self.root_cert_pem


def generate_keypair() -> Tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Generate an EC P-256 keypair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_key, private_key_pem


def generate_root_cert(private_key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    """Generate a self-signed root CA certificate."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Scittish"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Scittish Root CA"),
    ])
    
    public_key = private_key.public_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert


def generate_leaf_cert(
    leaf_private_key: ec.EllipticCurvePrivateKey,
    issuer_private_key: ec.EllipticCurvePrivateKey,
    issuer_cert: x509.Certificate,
) -> x509.Certificate:
    """Generate an end-entity certificate signed by the root CA."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Scittish"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Scittish Signing Key"),
    ])
    
    leaf_public_key = leaf_private_key.public_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(leaf_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.5.5.7.3.36")]),
            critical=False,
        )
        .sign(issuer_private_key, hashes.SHA256())
    )
    return cert


def generate_certificate_chain() -> CertificateChain:
    """Generate a complete certificate chain with root CA and leaf certificate."""
    # Generate root CA
    root_key, _ = generate_keypair()
    root_cert = generate_root_cert(root_key)
    root_cert_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    
    # Generate leaf certificate
    leaf_key, leaf_key_pem = generate_keypair()
    leaf_cert = generate_leaf_cert(leaf_key, root_key, root_cert)
    leaf_cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    
    return CertificateChain(
        root_cert_pem=root_cert_pem,
        leaf_cert_pem=leaf_cert_pem,
        leaf_key_pem=leaf_key_pem.decode("utf-8"),
    )


def save_certificate_chain(chain: CertificateChain, output_dir: Path) -> None:
    """Save the certificate chain and key to files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    (output_dir / "chain.pem").write_text(chain.chain_pem)
    (output_dir / "root.pem").write_text(chain.root_cert_pem)
    (output_dir / "leaf.pem").write_text(chain.leaf_cert_pem)
    (output_dir / "leaf_key.pem").write_text(chain.leaf_key_pem)


def load_certificate_chain(certs_dir: Path) -> Optional[CertificateChain]:
    """Load an existing certificate chain from files if present."""
    chain_file = certs_dir / "chain.pem"
    root_file = certs_dir / "root.pem"
    leaf_file = certs_dir / "leaf.pem"
    key_file = certs_dir / "leaf_key.pem"
    
    if all(f.exists() for f in [root_file, leaf_file, key_file]):
        return CertificateChain(
            root_cert_pem=root_file.read_text(),
            leaf_cert_pem=leaf_file.read_text(),
            leaf_key_pem=key_file.read_text(),
        )
    return None
