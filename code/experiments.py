#!/usr/bin/env python3
"""Task 3 - Security experiments (synthetic data only).

  A: ciphertext tampering against AES-GCM
  B: ECB vs CBC vs GCM  (pattern leakage, malleability, nonce reuse)
  C: key management (env-var / KMS-style envelope encryption + rotation)

Run:  python experiments.py [A|B|C]   (no argument = all)
"""
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aes_gcm_demo import CUSTOMER, decrypt_record, encrypt_record, generate_key


def hr(title):
    print("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70)


# ---------------------------------------------------------------- Experiment A
def experiment_a():
    hr("Experiment A: ciphertext modification (AES-256-GCM)")
    key = generate_key()
    blob = encrypt_record(key, CUSTOMER, b"CUST1001")
    ct = blob["ciphertext"]
    print("Original ciphertext :", ct.hex())

    tampered = bytearray(ct)
    idx = 5
    tampered[idx] ^= 0x01  # flip a single bit of one byte
    print(f"Tampered ciphertext : {bytes(tampered).hex()}  (byte {idx} XOR 0x01)")
    diff = [i for i in range(len(ct)) if ct[i] != tampered[i]]
    print("Differing byte positions:", diff)

    try:
        print("Decrypting original  ->", decrypt_record(key, blob))
        decrypt_record(key, {**blob, "ciphertext": bytes(tampered)})
        print("Decrypting tampered  -> UNEXPECTED SUCCESS")
    except ValueError as e:
        print("Decrypting tampered  -> REJECTED:", e)

    # Also tamper with tag and nonce
    for name in ("tag", "nonce"):
        mod = bytearray(blob[name]); mod[0] ^= 0xFF
        try:
            decrypt_record(key, {**blob, name: bytes(mod)})
        except ValueError:
            print(f"Modified {name:<5}        -> REJECTED")

    # Contrast: unauthenticated CTR mode silently accepts bit-flips
    print("\nContrast - AES-CTR (no authentication): attacker flips ciphertext bits")
    k, n = generate_key(), os.urandom(16)
    pt = b'{"Account Balance": 15000}'
    enc = Cipher(algorithms.AES(k), modes.CTR(n)).encryptor()
    c = bytearray(enc.update(pt) + enc.finalize())
    pos = pt.index(b"15000") + 0  # '1'
    c[pos] ^= ord("1") ^ ord("9")  # attacker turns '1' into '9' without the key
    dec = Cipher(algorithms.AES(k), modes.CTR(n)).decryptor()
    print("  Decrypted after attack:", (dec.update(bytes(c)) + dec.finalize()).decode(),
          " <- silently modified (balance 15000 -> 95000)")


# ---------------------------------------------------------------- Experiment B
def ecb_enc(key, data):
    p = padding.PKCS7(128).padder()
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(p.update(data) + p.finalize()) + e.finalize()


def cbc_enc(key, data):
    iv = os.urandom(16)
    p = padding.PKCS7(128).padder()
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + e.update(p.update(data) + p.finalize()) + e.finalize()


def blocks(b, n=16):
    return [b[i:i + n].hex() for i in range(0, len(b), n)]


def experiment_b():
    hr("Experiment B: AES-ECB vs AES-CBC vs AES-GCM")
    key = generate_key()

    # Structured records with fixed-width 16-byte fields (one AES block per field),
    # as in a typical fixed-width export: ID | Name | Currency+Status
    f = lambda *x: b"".join(v.ljust(16).encode() for v in x)
    rec1 = f("CUST1001", "Alice Smith", "EUR/ACTIVE")
    rec2 = f("CUST1002", "Bob Jones", "EUR/ACTIVE")
    rec3 = f("CUST1003", "Alice Smith", "EUR/ACTIVE")
    print("Records (3 fields x 16 bytes each):")
    for r in (rec1, rec2, rec3):
        print("  ", [r[i:i+16].decode().strip() for i in range(0, 48, 16)])

    print("\n-- ECB: first 4 hex bytes of each ciphertext block (equal plaintext block => equal ciphertext)")
    E = {n: blocks(ecb_enc(key, r)) for n, r in (("rec1", rec1), ("rec2", rec2), ("rec3", rec3))}
    for n, bl in E.items():
        print(f"  {n}:", [h[:8] for h in bl[:3]])
    print("  rec1 vs rec3 block equality [ID, Name, Cur/Status, pad]:", [x == y for x, y in zip(E["rec1"], E["rec3"])])
    print("  rec1 vs rec2 block equality [ID, Name, Cur/Status, pad]:", [x == y for x, y in zip(E["rec1"], E["rec2"])])
    print("  -> attacker sees WHICH customers share a name / currency / status without the key")

    print("\n-- ECB block swapping (no integrity): attacker swaps blocks without the key")
    ct = bytearray(ecb_enc(key, b"PAY:CUST1001....AMT:0000000100.."))
    ct[0:16], ct[16:32] = ct[16:32], ct[0:16]
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    print("  After swap, decrypts to:", (d.update(bytes(ct)) + d.finalize())[:32], "(accepted, no error)")

    print("\n-- CBC: random IV hides repeats, but NO integrity")
    c1, c3 = cbc_enc(key, rec1), cbc_enc(key, rec3)
    print("  any equal blocks between rec1/rec3 ciphertext?", bool(set(blocks(c1[16:])) & set(blocks(c3[16:]))))
    iv = os.urandom(16)
    p = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(p.update(b"Balance=0000015000;") + p.finalize()) + enc.finalize()
    forged_iv = bytearray(iv); forged_iv[8] ^= ord("1") ^ ord("9")  # first-block bit-flip via IV
    dec = Cipher(algorithms.AES(key), modes.CBC(bytes(forged_iv))).decryptor()
    out = dec.update(ct) + dec.finalize()
    print("  IV-bitflip changes plaintext predictably:", out, "(no error raised)")

    print("\n-- GCM: random nonce + authentication")
    g1 = encrypt_record(key, CUSTOMER)["ciphertext"]
    g2 = encrypt_record(key, CUSTOMER)["ciphertext"]
    print("  same record encrypted twice identical?", g1 == g2)

    print("\n-- GCM nonce REUSE (catastrophic misuse demo)")
    nonce = os.urandom(12)
    a = AESGCM(key)
    p1, p2 = b"Account Balance: 15000", b"Account Balance: 99999"
    c1, c2 = a.encrypt(nonce, p1, None)[:-16], a.encrypt(nonce, p2, None)[:-16]
    xor_ct = bytes(x ^ y for x, y in zip(c1, c2))
    xor_pt = bytes(x ^ y for x, y in zip(p1, p2))
    print("  C1 XOR C2 == P1 XOR P2 ?", xor_ct == xor_pt,
          " -> keystream reuse; knowing P1 reveals P2 (and enables tag forgery)")
    known = bytes(x ^ y for x, y in zip(xor_ct, p1))
    print("  Attacker recovers P2 from C1^C2 and known P1:", known)

    print("\nSummary table")
    rows = [("Mode", "Confidentiality", "Integrity", "Main implementation risks"),
            ("ECB", "Weak (patterns leak)", "None", "Deterministic; block reorder/replay"),
            ("CBC", "Good (random IV)", "None", "Needs MAC; padding oracle; IV mgmt"),
            ("GCM", "Strong", "Yes (128-bit tag)", "Nonce reuse is catastrophic")]
    for r in rows:
        print("  {:<5}{:<24}{:<20}{}".format(*r))


# ---------------------------------------------------------------- Experiment C
def wrap(kek, dek, label):  # AES-GCM key wrap with a context label as AAD
    n = os.urandom(12)
    return n + AESGCM(kek).encrypt(n, dek, label)


def unwrap(kek, blob, label):
    return AESGCM(kek).decrypt(blob[:12], blob[12:], label)


def experiment_c():
    hr("Experiment C: key management (envelope encryption + rotation)")
    print("Anti-pattern:   KEY = b'0123...'  # hard-coded -> lives in git history, builds,")
    print("                backups, logs; cannot be rotated without redeploy.\n")

    # The KEK would live in a KMS/HSM (AWS KMS, Azure Key Vault, HashiCorp Vault).
    # Here a random KEK stands in for it - never write it to disk in production.
    kek_v1 = generate_key()
    dek = generate_key()                           # per-dataset data-encryption key
    wrapped = wrap(kek_v1, dek, b"dek:customers:v1")
    print("1. DEK generated with CSPRNG; stored only WRAPPED by the KEK:", wrapped.hex()[:48] + "...")

    rec = encrypt_record(dek, CUSTOMER, b"CUST1001")
    print("2. Record encrypted with DEK (v1).")

    # Rotation: new KEK, re-wrap DEK (cheap); for DEK rotation re-encrypt data
    kek_v2 = generate_key()
    wrapped_v2 = wrap(kek_v2, unwrap(kek_v1, wrapped, b"dek:customers:v1"), b"dek:customers:v2")
    print("3. KEK rotated to v2: DEK re-wrapped, data NOT re-encrypted.")
    assert decrypt_record(unwrap(kek_v2, wrapped_v2, b"dek:customers:v2"), rec) == CUSTOMER
    print("   Record still decrypts via KEK v2 -> OK")

    dek2 = generate_key()
    rec2 = encrypt_record(dek2, decrypt_record(dek, rec), b"CUST1001")
    print("4. DEK rotated: record re-encrypted under DEK v2; old DEK destroyed.")
    try:
        decrypt_record(dek, rec2)
    except ValueError:
        print("   Old DEK can no longer decrypt new ciphertext -> OK")
    print("5. Production keys: HSM/KMS, IAM least-privilege, audit logs, env/secret-manager injection.")


if __name__ == "__main__":
    which = sys.argv[1].upper() if len(sys.argv) > 1 else "ABC"
    for ch, fn in (("A", experiment_a), ("B", experiment_b), ("C", experiment_c)):
        if ch in which:
            fn()
