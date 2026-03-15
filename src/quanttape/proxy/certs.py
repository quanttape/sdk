"""Certificate Authority manager for QuantTape Guard HTTPS inspection.

On first run, generates a local root CA certificate and private key at
~/.quanttape/ca.pem and ~/.quanttape/ca-key.pem. Per-host certificates
are generated on-the-fly and signed by this CA.

The user must trust the CA cert for full HTTPS inspection to work.
"""

import logging
import platform
import sys
from pathlib import Path
from typing import Tuple

logger = logging.getLogger("quanttape.guard")

CA_DIR = Path.home() / ".quanttape"
CA_KEY_FILE = CA_DIR / "ca-key.pem"
CA_CERT_FILE = CA_DIR / "ca.pem"
CERTS_DIR = CA_DIR / "certs"


def ensure_ca() -> Tuple[str, str]:
    """Generate a local CA key+cert if they don't exist.

    Returns:
        Tuple of (ca_key_path, ca_cert_path) as strings.

    Raises:
        ImportError: if cryptography package is not installed.
    """
    CA_DIR.mkdir(parents=True, exist_ok=True)
    if CA_KEY_FILE.exists() and CA_CERT_FILE.exists():
        return str(CA_KEY_FILE), str(CA_CERT_FILE)

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as dt
    except ImportError:
        raise ImportError(
            "HTTPS inspection requires 'cryptography' package.\n"
            "Install with: pip install quanttape[guard]"
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "QuantTape Guard CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QuantTape Local"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    CA_KEY_FILE.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    CA_CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    logger.info("Generated local CA at %s", CA_CERT_FILE)
    return str(CA_KEY_FILE), str(CA_CERT_FILE)


def make_host_cert(hostname: str, ca_key_path: str, ca_cert_path: str) -> Tuple[str, str]:
    """Generate an on-the-fly cert for a hostname, signed by the local CA.

    Handles both DNS hostnames and IP addresses correctly in the SAN.

    Returns:
        Tuple of (host_key_path, host_cert_path) as strings.
    """
    import ipaddress
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as dt

    ca_key = serialization.load_pem_private_key(
        Path(ca_key_path).read_bytes(), password=None
    )
    ca_cert = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())

    host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])

    # Use IPAddress SAN for IP addresses, DNSName for hostnames
    try:
        ip = ipaddress.ip_address(hostname)
        san_entries = [x509.IPAddress(ip)]
    except ValueError:
        san_entries = [x509.DNSName(hostname)]

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(host_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(host_key.public_key()),
            critical=False,
        )
    )

    host_cert = builder.sign(ca_key, hashes.SHA256())

    CERTS_DIR.mkdir(exist_ok=True)
    safe_name = hostname.replace("*", "_star_").replace(":", "_")
    cert_path = CERTS_DIR / f"{safe_name}.pem"
    key_path = CERTS_DIR / f"{safe_name}-key.pem"

    key_path.write_bytes(
        host_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(host_cert.public_bytes(serialization.Encoding.PEM))

    return str(key_path), str(cert_path)


def setup_certs_interactive():
    """Generate CA certs and print trust instructions for the user's platform."""
    try:
        ca_key_path, ca_cert_path = ensure_ca()
    except ImportError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\n  QuantTape Guard - Certificate Setup")
    print(f"  ====================================")
    print(f"\n  CA certificate: {ca_cert_path}")
    print(f"  CA private key: {ca_key_path}")

    os_name = platform.system()

    print(f"\n  --- Trust the CA for Python HTTP clients ---")
    print(f"  Add these to your shell profile (.bashrc, .zshrc, etc.):\n")
    print(f"    export REQUESTS_CA_BUNDLE={ca_cert_path}")
    print(f"    export SSL_CERT_FILE={ca_cert_path}")
    print(f"    export CURL_CA_BUNDLE={ca_cert_path}")
    print(f"    export NODE_EXTRA_CA_CERTS={ca_cert_path}")

    if os_name == "Darwin":
        print(f"\n  --- Trust system-wide (macOS) ---")
        print(f"    sudo security add-trusted-cert -d -r trustRoot \\")
        print(f"      -k /Library/Keychains/System.keychain {ca_cert_path}")
    elif os_name == "Linux":
        print(f"\n  --- Trust system-wide (Ubuntu/Debian) ---")
        print(f"    sudo cp {ca_cert_path} /usr/local/share/ca-certificates/quanttape-guard.crt")
        print(f"    sudo update-ca-certificates")
        print(f"\n  --- Trust system-wide (RHEL/Fedora) ---")
        print(f"    sudo cp {ca_cert_path} /etc/pki/ca-trust/source/anchors/quanttape-guard.pem")
        print(f"    sudo update-ca-trust")
    elif os_name == "Windows":
        print(f"\n  --- Trust system-wide (Windows) ---")
        print(f'    certutil -addstore "Root" "{ca_cert_path}"')
        print(f"    (Run as Administrator)")

    print(f"\n  --- Quick test ---")
    print(f"    quanttape guard --mode agent")
    print(f"    # In another terminal:")
    print(f"    export HTTPS_PROXY=http://127.0.0.1:8080")
    print(f"    export REQUESTS_CA_BUNDLE={ca_cert_path}")
    print(f'    python -c "import requests; print(requests.get(\'https://httpbin.org/get\').status_code)"')
    print()
