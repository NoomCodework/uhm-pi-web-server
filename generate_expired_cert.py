# Generates an already-expired self-signed cert for localhost using Python only (no openssl needed).
# Outputs: expired.key (PEM), expired.crt (PEM)

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

def main():
    # Key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Subject/Issuer (self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    # Validity entirely in the past
    now = datetime.now(timezone.utc)
    not_valid_before = now - timedelta(days=365*5 + 2)  # 5 years + 2 days ago
    not_valid_after = now - timedelta(days=365*5 + 1)   # 5 years + 1 day ago

    # SAN: localhost, 127.0.0.1, ::1
    alt_names = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ip_address("127.0.0.1")),
        x509.IPAddress(ip_address("::1")),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(alt_names, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    with open("expired.key", "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open("expired.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("Wrote expired.key and expired.crt")
    print(cert.not_valid_before_utc, "->", cert.not_valid_after_utc)

if __name__ == "__main__":
    main()