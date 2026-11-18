"""Bob's command-line program for verifying and decrypting a package."""

from __future__ import print_function

import argparse
import getpass
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from securelabs_crypto import CryptoError, decrypt_file  # noqa: E402


def build_parser():
    parser = argparse.ArgumentParser(
        description="Verify Alice's package and decrypt it with Bob's private key."
    )
    parser.add_argument("package", help="SecureLabs .slpkg file")
    parser.add_argument(
        "-o", "--output", help="Output file (default: signed original filename)"
    )
    return parser


def main():
    args = build_parser().parse_args()
    script_dir = Path(__file__).resolve().parent
    package_path = Path(args.package).resolve()
    try:
        output_path = (
            Path(args.output).resolve()
            if args.output
            else None
        )
        password = os.environ.get("BOB_KEY_PASSWORD")
        if password is None:
            password = getpass.getpass("Password for Bob's private key: ")
        result = decrypt_file(
            package_path=package_path,
            output_path=output_path,
            alice_certificate_path=script_dir / "alice_verifying_key.crt",
            ca_path=script_dir / "ca.crt",
            bob_private_key_path=script_dir / "bob_private_key.pem",
            bob_key_password=password,
        )
    except CryptoError as exc:
        print("Decryption failed: {}".format(exc), file=sys.stderr)
        return 1
    print("Verified and decrypted file: {}".format(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
