# graphspy/core/device.py

# Built-in imports
import base64
from datetime import datetime

# External library imports
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from loguru import logger

# Local library imports
from ..db import connection
from ..core import user_agent as ua
from .errors import AppError


def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_key, private_key_bytes, private_key.public_key()


def generate_public_key_rsa_blob(public_key) -> bytes:
    import struct

    pub = public_key.public_numbers()
    exp_bytes = pub.e.to_bytes((pub.e.bit_length() + 7) // 8, byteorder="big")
    mod_bytes = pub.n.to_bytes((pub.n.bit_length() + 7) // 8, byteorder="big")
    header = [
        b"RSA1",
        struct.pack("<L", public_key.key_size),
        struct.pack("<L", len(exp_bytes)),
        struct.pack("<L", len(mod_bytes)),
        struct.pack("<L", 0),
        struct.pack("<L", 0),
    ]
    return base64.b64encode(b"".join(header) + exp_bytes + mod_bytes)


def register(
    access_token_id: int,
    device_name: str = "GraphSpy-Device",
    join_type: int = 0,
    device_type: str = "Windows",
    os_version: str = "10.0.26100",
    target_domain: str = "e-corp.local",
) -> str:
    private_key, private_key_bytes, public_key = generate_key_pair()
    private_key_base64 = base64.b64encode(private_key_bytes).decode("utf-8")
    pubkeycngblob = generate_public_key_rsa_blob(public_key)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME, "7E980AD9-B86D-4306-9425-9AC066FB014A"
                    )
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )
    certbytes = base64.b64encode(csr.public_bytes(serialization.Encoding.DER))
    request_body = {
        "CertificateRequest": {"Type": "pkcs10", "Data": certbytes.decode("utf-8")},
        "TransportKey": pubkeycngblob.decode("utf-8"),
        "TargetDomain": target_domain,
        "DeviceType": device_type,
        "OSVersion": os_version,
        "DeviceDisplayName": device_name,
        "JoinType": join_type,
        "attributes": {"ReuseDevice": "true", "ReturnClientSid": "true"},
    }
    access_token = connection.query_db(
        "SELECT accesstoken FROM accesstokens WHERE id = ?", [access_token_id], one=True
    )[0]
    if not access_token:
        raise AppError(f"No access token with ID {access_token_id}!")
    response = requests.post(
        "https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=2.0",
        headers={"User-Agent": ua.get(), "Authorization": f"Bearer {access_token}"},
        json=request_body,
    )
    if response.status_code != 200:
        try:
            error_code = response.json().get("code", "Unknown error")
            error_msg = response.json().get("message", "Unknown error")
            raise AppError(
                f"Failed to register device.\n[{response.status_code}] {error_code}: {error_msg}"
            )
        except ValueError:
            raise AppError(f"Failed to register device.\n{response.text}")
    response_json = response.json()
    logger.debug(f"Device registration response:\n{response_json}")
    if "Certificate" not in response_json:
        raise AppError("Failed to register device. No certificate in response.")
    certificate_base64 = response_json["Certificate"]["RawBody"]
    certificate = x509.load_der_x509_certificate(base64.b64decode(certificate_base64))
    device_id = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    connection.execute_db(
        "INSERT INTO device_certificates (stored_at, device_id, device_name, device_type, join_type, priv_key, certificate) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            int(datetime.now().timestamp()),
            device_id,
            device_name,
            device_type,
            (
                "joined"
                if join_type == 0
                else "registered" if join_type == 4 else "unknown"
            ),
            private_key_base64,
            certificate_base64,
        ),
    )
    return device_id
