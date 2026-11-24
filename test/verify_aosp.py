"""Compare the built CLI with AOSP avbtool using temporary synthetic credentials."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import textwrap
from unittest.mock import patch
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parents[1]
AOSP_REVISION = "23c8439bb647e483b80f9bac6974798a06a4ae5f"
AOSP_SHA256 = "e2c888f783011496a486059d52162b03b3c16ffe8117789dba6bf76c7f69c617"
AOSP_SOURCE = f"https://android.googlesource.com/platform/external/avb/+/{AOSP_REVISION}/avbtool.py?format=TEXT"
AOSP_MIRROR = f"https://raw.githubusercontent.com/LineageOS/android_external_avb/{AOSP_REVISION}/avbtool.py"


def run(*args, cwd):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited with {result.returncode}\n{result.stderr}")
    return result.stdout


def get_avbtool(directory, local_file):
    if local_file:
        source = local_file.read_bytes()
    else:
        try:
            with urllib.request.urlopen(AOSP_SOURCE, timeout=15) as response:
                source = base64.b64decode(response.read(), validate=True)
        except (OSError, ValueError):
            with urllib.request.urlopen(AOSP_MIRROR, timeout=15) as response:
                source = response.read()
    if hashlib.sha256(source).hexdigest() != AOSP_SHA256:
        raise RuntimeError(f"avbtool.py does not match pinned AOSP revision {AOSP_REVISION}")

    reference = directory / "avbtool.py"
    reference.write_bytes(source)
    return reference


def make_archive(directory, name, key, compression, extras=()):
    with zipfile.ZipFile(directory / name, "w", compression) as archive:
        archive.write(directory / "pik.bin", "pik_certificate.test.bin")
        archive.write(directory / "puk.bin", "puk_certificate.test.bin")
        archive.write(directory / key, "puk.test.pem")
        for filename, content in extras:
            archive.writestr(filename, content)


def generate_fixtures(directory, reference):
    def avbtool(*args):
        return run(sys.executable, reference, *args, cwd=directory)

    product_id = bytes(range(16))
    nonce = bytes(range(240, 256))
    (directory / "product-id.bin").write_bytes(product_id)
    (directory / "nonce.bin").write_bytes(nonce)
    challenge = struct.pack("<I", 1) + hashlib.sha256(product_id).digest() + nonce
    (directory / "challenge.bin").write_bytes(challenge)

    for role in ("root", "pik", "puk"):
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096",
            "-out", f"{role}.pem", cwd=directory)
    run("openssl", "pkey", "-in", "puk.pem", "-traditional", "-out", "puk-pkcs1.pem", cwd=directory)

    avbtool("make_certificate", "--output", "pik.bin", "--subject_key", "pik.pem",
            "--subject", "product-id.bin", "--subject_key_version", "1",
            "--subject_is_intermediate_authority", "--authority_key", "root.pem")
    avbtool("make_certificate", "--output", "puk.bin", "--subject_key", "puk.pem",
            "--subject", "product-id.bin", "--subject_key_version", "2",
            "--usage_for_unlock", "--authority_key", "pik.pem")
    avbtool("make_cert_unlock_credential", "--output", "aosp.bin",
            "--intermediate_key_certificate", "pik.bin", "--unlock_key_certificate", "puk.bin",
            "--challenge", "nonce.bin", "--unlock_key", "puk.pem")

    make_archive(directory, "pkcs8.zip", "puk.pem", zipfile.ZIP_DEFLATED)
    make_archive(directory, "pkcs1.zip", "puk-pkcs1.pem", zipfile.ZIP_STORED)
    # Keep the classic directory fields while also writing a ZIP64 footer.
    with patch.object(zipfile, "ZIP_FILECOUNT_LIMIT", 0):
        make_archive(directory, "zip64.zip", "puk.pem", zipfile.ZIP_DEFLATED)


def verify_cli(directory):
    cli = ("node", ROOT / "dist" / "cli.js", "sign")
    challenge = ("--challenge", "challenge.bin")
    loose = ("--pik-cert", "pik.bin", "--puk-cert", "puk.bin", "--puk-key")
    expected = (directory / "aosp.bin").read_bytes()
    cases = {
        "ZIP (PKCS#8, deflated)": ("--bundle", "pkcs8.zip"),
        "ZIP (PKCS#1, stored)": ("--bundle", "pkcs1.zip"),
        "ZIP (both ZIP64 and classic footers)": ("--bundle", "zip64.zip"),
        "loose files (PKCS#8)": (*loose, "puk.pem"),
        "loose files (PKCS#1)": (*loose, "puk-pkcs1.pem"),
    }
    for index, (label, args) in enumerate(cases.items()):
        output = f"actual-{index}.bin"
        run(*cli, *challenge, *args, "--out", output, cwd=directory)
        if (directory / output).read_bytes() != expected:
            raise RuntimeError(f"{label} output differs from AOSP")
        print(f"PASS {label}: all {len(expected)} bytes match AOSP")

    def expect_error(label, message, args, output="rejected.bin"):
        result = subprocess.run((*cli, *args, "--out", output), cwd=directory,
                                capture_output=True, text=True, check=False)
        if result.returncode != 1 or message not in result.stderr:
            raise RuntimeError(f"{label}: unexpected exit {result.returncode}\n{result.stderr}")
        if output == "rejected.bin" and (directory / output).exists():
            raise RuntimeError(f"{label}: wrote an output file on error")
        print(f"PASS rejected {label}")

    expect_error("mismatched private key", "private key does not match", (*challenge, *loose, "pik.pem"))
    expect_error("ambiguous match", "Multiple credential bundles match",
                 (*challenge, "--bundle", "pkcs8.zip", "--bundle", "pkcs1.zip"))

    original = (directory / "challenge.bin").read_bytes()
    (directory / "other-product.bin").write_bytes(original[:4] + bytes(32) + original[36:])
    expect_error("wrong product", "No credential bundle matches",
                 ("--challenge", "other-product.bin", "--bundle", "pkcs8.zip"))
    (directory / "unsupported.bin").write_bytes(struct.pack("<I", 2) + original[4:])
    expect_error("unsupported challenge version", "Unsupported ATX challenge version 2",
                 ("--challenge", "unsupported.bin", "--bundle", "pkcs8.zip"))

    modified_puk = bytearray((directory / "puk.bin").read_bytes())
    modified_puk[-1] ^= 1
    (directory / "modified-puk.bin").write_bytes(modified_puk)
    expect_error("invalid PUK certificate signature", "does not verify the PUK certificate signature",
                 (*challenge, "--pik-cert", "pik.bin", "--puk-cert", "modified-puk.bin", "--puk-key", "puk.pem"))

    make_archive(directory, "duplicate.zip", "puk.pem", zipfile.ZIP_DEFLATED,
                 (("puk.extra.pem", b"duplicate"),))
    expect_error("duplicate ZIP role", "multiple PUK private key files",
                 (*challenge, "--bundle", "duplicate.zip"))

    expect_error("existing output", "EEXIST", (*challenge, "--bundle", "pkcs8.zip"), "actual-0.bin")
    if (directory / "actual-0.bin").read_bytes() != expected:
        raise RuntimeError("An existing credential was changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--avbtool", type=Path, help="Local copy of the pinned AOSP avbtool.py")
    parser.add_argument("--write-demo", type=Path, help="Write a fresh synthetic browser demo fixture")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="things-unlock-test-") as temp:
        directory = Path(temp)
        reference = get_avbtool(directory, args.avbtool)
        print(f"AOSP revision {AOSP_REVISION}", flush=True)
        generate_fixtures(directory, reference)
        verify_cli(directory)
        if args.write_demo:
            def encoded_fixture(name):
                return textwrap.wrap(base64.b64encode((directory / name).read_bytes()).decode(), 76)

            fixture = {
                "purpose": "Synthetic demo only. The private key is intentionally public and has no device trust chain.",
                "challenge": encoded_fixture("challenge.bin"),
                "bundle": encoded_fixture("pkcs8.zip"),
                "credentialSha256": hashlib.sha256((directory / "aosp.bin").read_bytes()).hexdigest(),
            }
            args.write_demo.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
