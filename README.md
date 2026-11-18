 SecureLabs File Encryption

This submission implements the two required command-line programs and all
three advanced features in the assignment rubric. The programs use the
university-supplied keys and certificates; they do not generate replacement
credentials. If this archive was received without those issued files, merge it
with the original assignment archive using the paths in
`INSTRUCTOR_FILES_REQUIRED.txt` before submission.

## Required supplied files

Keep the original files in these locations:

```text
alice/alice_signing_key.pem
alice/bob_public_key.crt
alice/ca.crt
alice/confidential_image.JPG
bob/alice_verifying_key.crt
bob/bob_private_key.pem
bob/ca.crt
```

## Install

```console
python -m pip install -r requirements.txt
```

## Encrypt as Alice

Run from the project root. The program prompts for the password protecting
Alice's private key.

```console
python alice/encrypt.py alice/confidential_image.JPG -o confidential_image.slpkg
```

Copy only `confidential_image.slpkg` into Bob's folder. It contains encrypted
data, a wrapped one-time AES key, public metadata, an authentication tag and
Alice's signature. It does not contain either private key.

## Decrypt as Bob

```console
python bob/decrypt.py bob/confidential_image.slpkg -o bob/confidential_image.JPG
```

The program validates Alice's certificate against `bob/ca.crt`, verifies the
ECDSA signature over the complete package, unwraps the AES key using Bob's RSA
private key, and checks the AES-GCM tag before publishing the recovered file.

For non-interactive testing, the key passwords may be supplied through the
`ALICE_KEY_PASSWORD` and `BOB_KEY_PASSWORD` environment variables. They are
never included in the encrypted package.
