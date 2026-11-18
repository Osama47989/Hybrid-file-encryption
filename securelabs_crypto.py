from __future__ import print_function
import base64
import json
import os
import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


MAGIC = b"SLPKG1\r\n"
HEADER_LIMIT = 64 * 1024
TAG_LENGTH = 16
CHUNK_SIZE = 1024 * 1024
SIGNATURE_DOMAIN = b"SecureLabs signed package v1\x00"
OAEP_LABEL = b"SecureLabs AES-256-GCM key v1"


class CryptoError(Exception):


def _read_exact(handle, size, description):
    data = handle.read(size)
    if len(data) != size:
        raise CryptoError("Package ended while reading {}.".format(description))
    return data


def _b64encode(data):
    return base64.b64encode(data).decode("ascii")


def _b64decode(value, field_name):
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, TypeError, UnicodeError):
        raise CryptoError("Header field '{}' is not valid Base64.".format(field_name))


def _certificate_time(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _verify_certificate_signature(certificate, issuer_public_key):
    try:
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm),
            )
        else:
            raise CryptoError("The CA uses an unsupported public-key algorithm.")
    except InvalidSignature:
        raise CryptoError("The certificate signature is not valid for the trusted CA.")


def _optional_extension(certificate, extension_type):
    try:
        return certificate.extensions.get_extension_for_class(extension_type).value
    except x509.ExtensionNotFound:
        return None


def load_and_validate_certificate(certificate_path, ca_path, purpose):
    """Validate a leaf certificate against the explicitly trusted CA file."""
    try:
        certificate = x509.load_pem_x509_certificate(Path(certificate_path).read_bytes())
        ca_certificate = x509.load_pem_x509_certificate(Path(ca_path).read_bytes())
    except (OSError, ValueError) as exc:
        raise CryptoError("Could not load a certificate: {}".format(exc))

    if certificate.issuer != ca_certificate.subject:
        raise CryptoError("The certificate issuer does not match the trusted CA.")

    ca_constraints = _optional_extension(ca_certificate, x509.BasicConstraints)
    if ca_constraints is not None and not ca_constraints.ca:
        raise CryptoError("The trusted certificate is not authorised as a CA.")

    if ca_certificate.subject == ca_certificate.issuer:
        _verify_certificate_signature(ca_certificate, ca_certificate.public_key())
    _verify_certificate_signature(certificate, ca_certificate.public_key())

    now = datetime.now(timezone.utc)
    not_before = getattr(certificate, "not_valid_before_utc", None)
    not_after = getattr(certificate, "not_valid_after_utc", None)
    if not_before is None:
        not_before = _certificate_time(certificate.not_valid_before)
    if not_after is None:
        not_after = _certificate_time(certificate.not_valid_after)
    if now < not_before or now > not_after:
        raise CryptoError("The certificate is outside its validity period.")

    leaf_constraints = _optional_extension(certificate, x509.BasicConstraints)
    if leaf_constraints is not None and leaf_constraints.ca:
        raise CryptoError("A CA certificate cannot be used as an end-entity certificate.")

    key_usage = _optional_extension(certificate, x509.KeyUsage)
    public_key = certificate.public_key()
    if purpose == "encryption":
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise CryptoError("Bob's certificate must contain an RSA public key.")
        if public_key.key_size < 2048:
            raise CryptoError("Bob's RSA key must be at least 2048 bits.")
        if key_usage is not None and not key_usage.key_encipherment:
            raise CryptoError("Bob's certificate does not permit key encipherment.")
    elif purpose == "signature":
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise CryptoError("Alice's certificate must contain an EC public key.")
        if public_key.curve.name not in ("secp256r1", "prime256v1"):
            raise CryptoError("Alice's certificate must use the NIST P-256 curve.")
        if key_usage is not None and not key_usage.digital_signature:
            raise CryptoError("Alice's certificate does not permit digital signatures.")
    else:
        raise ValueError("Unknown certificate purpose.")
    return certificate


def load_private_key(key_path, password, expected_type):
    try:
        key = serialization.load_pem_private_key(
            Path(key_path).read_bytes(),
            password=password.encode("utf-8") if password is not None else None,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise CryptoError("Could not unlock the private key: {}".format(exc))
    if expected_type == "ec" and not isinstance(key, ec.EllipticCurvePrivateKey):
        raise CryptoError("Alice's private key is not an EC signing key.")
    if expected_type == "rsa" and not isinstance(key, rsa.RSAPrivateKey):
        raise CryptoError("Bob's private key is not an RSA decryption key.")
    return key


def _canonical_header(header):
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_header(header_bytes):
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise CryptoError("The package header is not valid canonical JSON.")
    required = {
        "version", "original_name", "plaintext_size", "ciphertext_size",
        "content_cipher", "key_transport", "signature_algorithm", "nonce",
        "wrapped_key",
    }
    if not isinstance(header, dict) or set(header) != required:
        raise CryptoError("The package header has an unexpected set of fields.")
    if header["version"] != 1:
        raise CryptoError("This package version is not supported.")
    if header["content_cipher"] != "AES-256-GCM":
        raise CryptoError("The content-cipher identifier is not supported.")
    if header["key_transport"] != "RSA-OAEP-SHA256":
        raise CryptoError("The key-transport identifier is not supported.")
    if header["signature_algorithm"] != "ECDSA-P256-SHA256":
        raise CryptoError("The signature identifier is not supported.")
    if not isinstance(header["plaintext_size"], int) or header["plaintext_size"] < 0:
        raise CryptoError("The plaintext size is invalid.")
    if header["ciphertext_size"] != header["plaintext_size"]:
        raise CryptoError("The ciphertext size is inconsistent with AES-GCM.")
    name = header["original_name"]
    if not isinstance(name, str) or not name or Path(name).name != name or "\x00" in name:
        raise CryptoError("The original filename is unsafe.")
    nonce = _b64decode(header["nonce"], "nonce")
    if len(nonce) != 12:
        raise CryptoError("AES-GCM requires a 96-bit nonce in this format.")
    wrapped_key = _b64decode(header["wrapped_key"], "wrapped_key")
    return header, nonce, wrapped_key


def encrypt_file(input_path, output_path, bob_certificate_path, ca_path,
                 alice_private_key_path, alice_key_password):
    input_path = Path(input_path)
    output_path = Path(output_path)
    if not input_path.is_file():
        raise CryptoError("Input file does not exist: {}".format(input_path))

    bob_certificate = load_and_validate_certificate(
        bob_certificate_path, ca_path, "encryption"
    )
    alice_private_key = load_private_key(
        alice_private_key_path, alice_key_password, "ec"
    )
    if alice_private_key.curve.name not in ("secp256r1", "prime256v1"):
        raise CryptoError("Alice's signing key must use the NIST P-256 curve.")

    file_key = os.urandom(32)
    nonce = os.urandom(12)
    wrapped_key = bob_certificate.public_key().encrypt(
        file_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=OAEP_LABEL,
        ),
    )
    plaintext_size = input_path.stat().st_size
    header = {
        "version": 1,
        "original_name": input_path.name,
        "plaintext_size": plaintext_size,
        "ciphertext_size": plaintext_size,
        "content_cipher": "AES-256-GCM",
        "key_transport": "RSA-OAEP-SHA256",
        "signature_algorithm": "ECDSA-P256-SHA256",
        "nonce": _b64encode(nonce),
        "wrapped_key": _b64encode(wrapped_key),
    }
    header_bytes = _canonical_header(header)
    if len(header_bytes) > HEADER_LIMIT:
        raise CryptoError("The package header is unexpectedly large.")
    prefix = MAGIC + struct.pack("!I", len(header_bytes))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(output_path.name + ".part")
    encryptor = Cipher(algorithms.AES(file_key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(prefix + header_bytes)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(SIGNATURE_DOMAIN)
    digest.update(prefix)
    digest.update(header_bytes)
    processed = 0

    try:
        with input_path.open("rb") as source, temporary_path.open("wb") as target:
            target.write(prefix)
            target.write(header_bytes)
            while True:
                block = source.read(CHUNK_SIZE)
                if not block:
                    break
                processed += len(block)
                encrypted = encryptor.update(block)
                target.write(encrypted)
                digest.update(encrypted)
            final_bytes = encryptor.finalize()
            if final_bytes:
                target.write(final_bytes)
                digest.update(final_bytes)
            if processed != plaintext_size:
                raise CryptoError("The input file changed while it was being encrypted.")
            tag = encryptor.tag
            target.write(tag)
            digest.update(tag)
            signature = alice_private_key.sign(
                digest.finalize(), ec.ECDSA(Prehashed(hashes.SHA256()))
            )
            if len(signature) > 65535:
                raise CryptoError("The signature is too large for this package format.")
            target.write(struct.pack("!H", len(signature)))
            target.write(signature)
        os.replace(str(temporary_path), str(output_path))
    except Exception:
        try:
            temporary_path.unlink()
        except OSError:
            pass
        raise
    return output_path


def _inspect_and_verify_package(package_path, alice_certificate):
    package_path = Path(package_path)
    package_size = package_path.stat().st_size
    with package_path.open("rb") as handle:
        magic = _read_exact(handle, len(MAGIC), "format marker")
        if magic != MAGIC:
            raise CryptoError("The input is not a SecureLabs package.")
        length_bytes = _read_exact(handle, 4, "header length")
        header_length = struct.unpack("!I", length_bytes)[0]
        if header_length == 0 or header_length > HEADER_LIMIT:
            raise CryptoError("The package header length is invalid.")
        header_bytes = _read_exact(handle, header_length, "header")
        header, nonce, wrapped_key = _parse_header(header_bytes)
        ciphertext_offset = handle.tell()
        ciphertext_size = header["ciphertext_size"]
        minimum_size = ciphertext_offset + ciphertext_size + TAG_LENGTH + 2
        if package_size < minimum_size:
            raise CryptoError("The package is shorter than its authenticated header declares.")

        digest = hashes.Hash(hashes.SHA256())
        digest.update(SIGNATURE_DOMAIN)
        digest.update(magic + length_bytes)
        digest.update(header_bytes)
        remaining = ciphertext_size
        while remaining:
            block = handle.read(min(CHUNK_SIZE, remaining))
            if not block:
                raise CryptoError("The package ended inside the ciphertext.")
            digest.update(block)
            remaining -= len(block)
        tag = _read_exact(handle, TAG_LENGTH, "authentication tag")
        digest.update(tag)
        signature_length = struct.unpack("!H", _read_exact(handle, 2, "signature length"))[0]
        if signature_length == 0:
            raise CryptoError("The package does not contain a signature.")
        signature = _read_exact(handle, signature_length, "signature")
        if handle.read(1):
            raise CryptoError("Unexpected data follows the package signature.")
        try:
            alice_certificate.public_key().verify(
                signature,
                digest.finalize(),
                ec.ECDSA(Prehashed(hashes.SHA256())),
            )
        except InvalidSignature:
            raise CryptoError("Alice's package signature is invalid.")
    return {
        "header": header,
        "header_bytes": header_bytes,
        "prefix": magic + length_bytes,
        "ciphertext_offset": ciphertext_offset,
        "ciphertext_size": ciphertext_size,
        "tag": tag,
        "nonce": nonce,
        "wrapped_key": wrapped_key,
    }


def decrypt_file(package_path, output_path, alice_certificate_path, ca_path,
                 bob_private_key_path, bob_key_password):
    package_path = Path(package_path)
    if not package_path.is_file():
        raise CryptoError("Encrypted package does not exist: {}".format(package_path))

    alice_certificate = load_and_validate_certificate(
        alice_certificate_path, ca_path, "signature"
    )
    package = _inspect_and_verify_package(package_path, alice_certificate)
    if output_path is None:
        output_path = Path.cwd() / package["header"]["original_name"]
    else:
        output_path = Path(output_path)
    bob_private_key = load_private_key(bob_private_key_path, bob_key_password, "rsa")
    if bob_private_key.key_size < 2048:
        raise CryptoError("Bob's RSA key must be at least 2048 bits.")
    try:
        file_key = bob_private_key.decrypt(
            package["wrapped_key"],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=OAEP_LABEL,
            ),
        )
    except ValueError:
        raise CryptoError("Bob's private key cannot recover the package key.")
    if len(file_key) != 32:
        raise CryptoError("The recovered AES key has an invalid length.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=output_path.name + ".", suffix=".part", dir=str(output_path.parent)
    )
    os.close(file_descriptor)
    temporary_path = Path(temporary_name)
    decryptor = Cipher(
        algorithms.AES(file_key), modes.GCM(package["nonce"], package["tag"])
    ).decryptor()
    decryptor.authenticate_additional_data(package["prefix"] + package["header_bytes"])

    try:
        with package_path.open("rb") as source, temporary_path.open("wb") as target:
            source.seek(package["ciphertext_offset"])
            remaining = package["ciphertext_size"]
            while remaining:
                block = source.read(min(CHUNK_SIZE, remaining))
                if not block:
                    raise CryptoError("The package ended inside the ciphertext.")
                target.write(decryptor.update(block))
                remaining -= len(block)
            try:
                target.write(decryptor.finalize())
            except InvalidTag:
                raise CryptoError("AES-GCM authentication failed; no plaintext was released.")
        if temporary_path.stat().st_size != package["header"]["plaintext_size"]:
            raise CryptoError("The decrypted file length does not match the signed header.")
        os.replace(str(temporary_path), str(output_path))
    except Exception:
        try:
            temporary_path.unlink()
        except OSError:
            pass
        raise
    return output_path
