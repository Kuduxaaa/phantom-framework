"""
CA and per-domain certificate management for MITM TLS interception.

On first run, generates a root CA and saves it to ~/.ph-proxy/.
The user must install ca.pem in their browser/system trust store
to avoid certificate warnings.
"""

import datetime
import logging
import os
import ssl
import tempfile
from typing import Dict, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger('ph-proxy.certs')

CA_DIR = os.path.join(os.path.expanduser('~'), '.ph-proxy')


class CertManager:
    """
    Manages the PhProxy CA and generates per-domain certificates
    on the fly for MITM TLS interception.
    """

    def __init__(self, ca_dir: str = CA_DIR) -> None:
        self._ca_dir = ca_dir
        os.makedirs(ca_dir, exist_ok=True)

        self._ca_cert_path = os.path.join(ca_dir, 'ca.pem')
        self._ca_key_path  = os.path.join(ca_dir, 'ca-key.pem')

        self._ctx_cache: Dict[str, ssl.SSLContext] = {}

        self._ca_key, self._ca_cert = self._load_or_create_ca()

    @property
    def ca_cert_path(self) -> str:
        return self._ca_cert_path

    def get_context(self, hostname: str) -> ssl.SSLContext:
        """
        Return an SSLContext with a certificate for the given hostname,
        signed by our CA. Caches contexts in memory.
        """

        if hostname not in self._ctx_cache:
            self._ctx_cache[hostname] = self._build_context(hostname)

        return self._ctx_cache[hostname]

    # ── CA management ─────────────────────────────────────────

    def _load_or_create_ca(self):
        if os.path.exists(self._ca_cert_path) and os.path.exists(self._ca_key_path):
            logger.info('Loading CA from %s', self._ca_dir)

            with open(self._ca_key_path, 'rb') as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self._ca_cert_path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())

            return key, cert

        logger.info('Generating new CA in %s', self._ca_dir)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        now = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'PhProxy CA'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Phantom Framework'),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        with open(self._ca_key_path, 'wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(self._ca_cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        return key, cert

    # ── Per-domain cert generation ────────────────────────────

    def _build_context(self, hostname: str) -> ssl.SSLContext:
        cert_pem, key_pem = self._generate_cert(hostname)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        cert_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pem')
        key_file  = tempfile.NamedTemporaryFile(delete=False, suffix='.pem')

        try:
            cert_file.write(cert_pem)
            cert_file.close()
            key_file.write(key_pem)
            key_file.close()
            ctx.load_cert_chain(cert_file.name, key_file.name)
        finally:
            os.unlink(cert_file.name)
            os.unlink(key_file.name)

        return ctx

    def _generate_cert(self, hostname: str) -> Tuple[bytes, bytes]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        now = datetime.datetime.now(datetime.timezone.utc)

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ]))
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return cert_pem, key_pem
