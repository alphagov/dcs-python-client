#!/usr/bin/env python3
"""
Make a test passport request to the Document Checking Service (DCS)

Usage: dcs-client [--url <url>] --client-signing-certificate <PATH> --client-signing-key <PATH> --server-encryption-certificate <PATH> --client-encryption-key <PATH> --server-signing-certificate <PATH> --client-ssl-certificate <PATH> --client-ssl-key <PATH> --server-ssl-ca-bundle <PATH>

Options:
    -h --help                               Show this screen.
    --url <url>                             The DCS passport endpoint [default: https://dcs-integration.ida.digital.cabinet-office.gov.uk/checks/passport]
    --client-signing-certificate <PATH>     The certificate with which the client signs requests
    --client-signing-key <PATH>             The key with which the client signs requests
    --server-encryption-certificate <PATH>  The server certificate for which the client encrypts requests
    --client-encryption-key <PATH>          The key with which the client decrypts responses
    --server-signing-certificate <PATH>     The certificate with which the server signs responses
    --client-ssl-certificate <PATH>         The client certificate used for mutual TLS
    --client-ssl-key <PATH>                 The client key used for mutual TLS
    --server-ssl-ca-bundle <PATH>           The server SSL CA bundle

This client is intended as an example of how to write a DCS client. It should not be used against a production DCS.
See https://dcs-pilot-docs.cloudapps.digital/ for public documentation of the DCS API.
"""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from datetime import datetime
from docopt import docopt
from jwcrypto import jwk, jws, jwe
from jwcrypto.common import json_encode, json_decode
import base64
import requests
import urllib.parse
import uuid


def create_valid_passport_request_payload():
    """
    Create a test passport request message payload

    Uses the details for a test passport that a test DCS instance will accept as valid.
    """
    return {
        "correlationId": str(uuid.uuid4()),
        "requestId": str(uuid.uuid4()),
        "timestamp": f"{datetime.utcnow().isoformat(timespec='milliseconds')}Z",
        "passportNumber": "824159121",
        "surname": "Watson",
        "forenames": ["Mary"],
        "dateOfBirth": "1932-02-25",
        "expiryDate": "2021-03-01",
    }


def sign(message, signing_key, sha1_thumbprint, sha256_thumbprint):
    """Create a signature layer for a message for DCS"""
    jwstoken = jws.JWS(payload=message)
    jwstoken.add_signature(
        key=signing_key,
        alg=None,
        protected=json_encode(
            {"alg": "RS256", "x5t": sha1_thumbprint, "x5t#S256": sha256_thumbprint}
        ),
    )
    return jwstoken.serialize(compact=True)


def encrypt(message, encryption_certificate):
    """Encrypt a message for DCS"""
    protected_header = {"alg": "RSA-OAEP-256", "enc": "A128CBC-HS256", "typ": "JWE"}
    jwetoken = jwe.JWE(
        plaintext=message, recipient=encryption_certificate, protected=protected_header
    )
    return jwetoken.serialize(compact=True)


def decrypt(message, encryption_key):
    """Decrypt a response from DCS"""
    jwetoken = jwe.JWE()
    jwetoken.deserialize(raw_jwe=message, key=encryption_key)
    return jwetoken.payload.decode("utf-8")


def unwrap_signature(message, signing_certificate):
    """Validate and strip a signature from a response from DCS"""
    jwstoken = jws.JWS()
    jwstoken.deserialize(raw_jws=message, key=signing_certificate)
    return jwstoken.payload.decode("utf-8")


def load_pem(path):
    """
    Load a PEM-formatted key or certificate

    Parsing will fail if the file contains anything other than the PEM-formatted key/certificate.
    """
    with open(path, "rb") as f:
        return jwk.JWK.from_pem(f.read())


def generate_thumbprints(path):
    """Generate the thumbprints needed for the `x5t` and `x5t256` headers"""
    with open(path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    sha1_thumbprint = (
        base64.urlsafe_b64encode(
            cert.fingerprint(hashes.SHA1())
        )  # The thumbprint is a URL-encoded hash...
        .decode("utf-8")  # ... as a Python string ...
        .strip("=")  # ... with the padding removed.
    )

    sha256_thumbprint = (
        base64.urlsafe_b64encode(
            cert.fingerprint(hashes.SHA256())
        )  # The thumbprint is a URL-encoded hash...
        .decode("utf-8")  # ... as a Python string ...
        .strip("=")  # ... with the padding removed.
    )

    return sha1_thumbprint, sha256_thumbprint


def wrap_request_payload(unwrapped_payload, arguments):
    """Wrap the request payload

    A DCS request payload must be signed, encrypted, and then signed again.

    See https://dcs-pilot-docs.cloudapps.digital/message-structure for the documentation.
    """
    client_signing_key = load_pem(arguments["--client-signing-key"])
    server_encryption_certificate = load_pem(
        arguments["--server-encryption-certificate"]
    )
    client_sha1_thumbprint, client_sha256_thumbprint = generate_thumbprints(
        arguments["--client-signing-certificate"]
    )

    inner_signed = sign(
        json_encode(unwrapped_payload),
        client_signing_key,
        client_sha1_thumbprint,
        client_sha256_thumbprint,
    )
    encrypted = encrypt(inner_signed, server_encryption_certificate)
    return sign(
        encrypted, client_signing_key, client_sha1_thumbprint, client_sha256_thumbprint
    )


def unwrap_response(body_data, arguments):
    """Unwrap the response payload

    DCS signed, encrypted, and then signed the plaintext response.

    See https://dcs-pilot-docs.cloudapps.digital/message-structure for the documentation.
    """
    server_signing_certificate = load_pem(arguments["--server-signing-certificate"])
    client_encryption_key = load_pem(arguments["--client-encryption-key"])

    encrypted = unwrap_signature(body_data, server_signing_certificate)
    inner_signed = decrypt(encrypted, client_encryption_key)
    return json_decode(unwrap_signature(inner_signed, server_signing_certificate))


def main():
    arguments = docopt(__doc__)

    request_payload_unwrapped = create_valid_passport_request_payload()
    print(f"Request: {request_payload_unwrapped}")
    request_payload_wrapped = wrap_request_payload(request_payload_unwrapped, arguments)

    r = requests.post(
        arguments["--url"],
        data=request_payload_wrapped,
        headers={"content-type": "application/jose",},
        cert=(arguments["--client-ssl-certificate"], arguments["--client-ssl-key"]),
        verify=arguments["--server-ssl-ca-bundle"],
    )
    r.raise_for_status()

    response_payload_unwrapped = unwrap_response(r.content.decode("utf-8"), arguments)
    print(f"\n\nResponse: {response_payload_unwrapped}")
