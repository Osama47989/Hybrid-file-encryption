"""Alice's command-line program for encrypting and signing a file."""

from __future__ import print_function

import argparse
import getpass
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from securelabs_crypto import CryptoError, encrypt_file  # noqa: E402


def build_parser():
    parser = argparse.ArgumentParser(
        description="Encrypt a file for Bob and sign the package as Alice."
    )
    parser.add_argument("input_file", help="File to encrypt")
    parser.add_argument(
        "-o", "--output", help="Output package (default: INPUT.slpkg)"
    )
    return parser


def main():
    args = build_parser().parse_args()
    input_path = Path(args.input_file).resolve()
    output_path = (
        Path(args.output).resolve()
        if args.output
        else input_path.with_name(input_path.name + ".slpkg")
    )
    script_dir = Path(__file__).resolve().parent
    password = os.environ.get("ALICE_KEY_PASSWORD")
    if password is None:
        password = getpass.getpass("Password for Alice's signing key: ")
    try:
        result = encrypt_file(
            input_path=input_path,
            output_path=output_path,
            bob_certificate_path=script_dir / "bob_public_key.crt",
            ca_path=script_dir / "ca.crt",
            alice_private_key_path=script_dir / "alice_signing_key.pem",
            alice_key_password=password,
        )
    except CryptoError as exc:
        print("Encryption failed: {}".format(exc), file=sys.stderr)
        return 1
    print("Encrypted package created: {}".format(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
