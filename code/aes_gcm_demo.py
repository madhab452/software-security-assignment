#!/usr/bin/env python3
"""Task 2 - AES-256-GCM encryption/decryption of a (synthetic) customer record.

Uses the `cryptography` library (AESGCM primitive). AES is NOT implemented by hand.
Run:  python aes_gcm_demo.py
"""
import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12  # 96-bit nonce: the size recommended by NIST SP 800-38D
TAG_LEN = 16    # GCM tag is 128 bits and is appended to the ciphertext


def generate_key() -> bytes:
    """256-bit key from the OS CSPRNG (os.urandom) via the library helper."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_record(key: bytes, record: dict, aad: bytes = b"") -> dict:
    """Encrypt a record. A fresh random nonce is generated for EVERY call.

    `aad` (associated data) is authenticated but not encrypted - it binds the
    ciphertext to its context (e.g. the customer ID / table name).
    Returns nonce, ciphertext and tag separately for display/storage.
    """
    nonce = os.urandom(NONCE_LEN)
    plaintext = json.dumps(record, sort_keys=True).encode("utf-8")
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        "nonce": nonce,
        "ciphertext": ct_and_tag[:-TAG_LEN],
        "tag": ct_and_tag[-TAG_LEN:],
        "aad": aad,
    }


def decrypt_record(key: bytes, blob: dict) -> dict:
    """Decrypt and verify. Raises ValueError on ANY failure (tamper, wrong key...).

    The caller never receives unauthenticated plaintext: GCM verifies the tag
    before releasing data.
    """
    try:
        pt = AESGCM(key).decrypt(
            blob["nonce"], blob["ciphertext"] + blob["tag"], blob["aad"]
        )
        return json.loads(pt.decode("utf-8"))
    except InvalidTag:
        # Deliberately generic message: do not leak why verification failed.
        raise ValueError("Decryption failed: authentication tag mismatch "
                         "(wrong key, wrong nonce/AAD, or data was modified)") from None
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Decryption failed: malformed input ({type(exc).__name__})") from None


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


# Synthetic data only (as required by the assignment)
CUSTOMER = {
    "Customer_ID": "CUST1001",
    "Name": "Alice Smith",
    "Account Balance": 15000,
    "Currency": "EUR",
}


def main() -> None:
    print("=== Task 2: AES-256-GCM demo ===")
    key = generate_key()
    print(f"[1] Key generated: {len(key)*8}-bit (value intentionally NOT printed in full)")
    print(f"    key fingerprint (first 4 bytes hex): {key[:4].hex()}...  [demo only]")

    print("\n[2] Plaintext record:")
    print("    " + json.dumps(CUSTOMER))

    aad = CUSTOMER["Customer_ID"].encode()
    blob = encrypt_record(key, CUSTOMER, aad)

    print("\n[3] Encrypted output")
    print(f"    Nonce  (12 B) hex   : {blob['nonce'].hex()}")
    print(f"    Cipher ({len(blob['ciphertext'])} B) hex   : {blob['ciphertext'].hex()}")
    print(f"    Tag    (16 B) hex   : {blob['tag'].hex()}")
    print(f"    Nonce  base64       : {b64(blob['nonce'])}")
    print(f"    Cipher base64       : {b64(blob['ciphertext'])}")
    print(f"    Tag    base64       : {b64(blob['tag'])}")
    print(f"    AAD (authenticated, not encrypted): {aad.decode()}")

    print("\n[4] Decryption with correct key")
    recovered = decrypt_record(key, blob)
    print("    Recovered:", json.dumps(recovered))
    print("    Matches original:", recovered == CUSTOMER)

    print("\n[5] Exception handling")
    wrong_key = generate_key()
    for label, k, b in [
        ("wrong key", wrong_key, blob),
        ("wrong AAD", key, {**blob, "aad": b"CUST9999"}),
        ("truncated tag", key, {**blob, "tag": blob["tag"][:8]}),
    ]:
        try:
            decrypt_record(k, b)
            print(f"    {label}: UNEXPECTED SUCCESS")
        except ValueError as e:
            print(f"    {label}: caught -> {e}")


if __name__ == "__main__":
    main()
