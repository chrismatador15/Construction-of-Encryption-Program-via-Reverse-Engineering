#!/usr/bin/env python3
"""
encrypt_11.py  –  CS 4653 Team 11
Reimplements the 4-step cipher found in Decrypt.exe.

Encryption order (matches Decrypt.exe):
  Step 1: Nibble transform    out = -(low_nibble << 4)  mod 256
  Step 2: XOR with key byte   key = LOOKUP[pwdHash[sel] & 7]
  Step 3: Rotate right 1 bit
  Step 4: Bit-pair swap       bits 0↔2, 1↔3, 4↔6, 5↔7

Decryption order (reverse):
  Step 1: Undo bit-pair swap
  Step 2: Rotate left  1 bit
  Step 3: XOR with same key byte
  Step 4: Undo nibble transform  (enumerates 16 candidates; uses hint byte to pick)

Usage:
    python encrypt_11.py encrypt <input_file> <output_file> <password>
    python encrypt_11.py decrypt <input_file> <output_file> <password>

NOTE: The nibble transform is lossy (discards the high nibble).
      Decryption selects candidate[0] (high_nibble = 0) for each byte.
      Pass --hint <hex_byte> as the expected first byte of plaintext to
      auto-select the correct candidate for byte 0, or post-process the
      output using known file-header magic.
"""

import sys

# ---------------------------------------------------------------------------
# XOR lookup table extracted from Decrypt.exe assembly
# ---------------------------------------------------------------------------
LOOKUP = [0xA5, 0x5A, 0xC3, 0x7E, 0xAC, 0x18, 0x69, 0x59]


# ---------------------------------------------------------------------------
# Password hashing
# NOTE: Replace the body of hash_password() with the real algorithm once
#       it has been extracted from the binary.  The placeholder below uses
#       a cycled-XOR scheme that produces deterministic output matching the
#       field widths used by the cipher (32 bytes).
# ---------------------------------------------------------------------------
def hash_password(password):
    """SHA-256 of the password — confirmed from Decrypt.exe string analysis."""
    import hashlib
    return hashlib.sha256(password.encode("utf-8")).digest()


# ---------------------------------------------------------------------------
# Step helpers
# ---------------------------------------------------------------------------
def nibble_encrypt(b):
    """Step 1 (encrypt): out = -(low_nibble << 4) mod 256"""
    low = b & 0x0F
    return (-(low << 4)) & 0xFF


def nibble_decrypt_candidates(cipher):
    """Step 1 (decrypt): enumerate all 16 preimages."""
    for n in range(16):
        if (-(n << 4)) & 0xFF == cipher:
            return [(hi << 4) | n for hi in range(16)]
    return []  # cipher is not a valid nibble-transform output


def rotate_right_1(b):
    """Step 3 (encrypt)"""
    return ((b >> 1) | (b << 7)) & 0xFF


def rotate_left_1(b):
    """Step 3 (decrypt) – inverse of rotate_right_1"""
    return ((b << 1) | (b >> 7)) & 0xFF


def bit_pair_swap(b):
    """Steps 4 (encrypt) and 1 (decrypt) – self-inverse.
    Swaps bit pairs: 0↔2, 1↔3, 4↔6, 5↔7
    """
    bits = [(b >> i) & 1 for i in range(8)]
    # swap 0↔2, 1↔3, 4↔6, 5↔7
    bits[0], bits[2] = bits[2], bits[0]
    bits[1], bits[3] = bits[3], bits[1]
    bits[4], bits[6] = bits[6], bits[4]
    bits[5], bits[7] = bits[7], bits[5]
    return sum(bits[i] << i for i in range(8))


def xor_key_for_index(pwd_hash, idx):
    """Step 2: derive per-byte XOR key from password hash."""
    selector = pwd_hash[8] if (idx & 4) else pwd_hash[23]
    return LOOKUP[selector & 7]


# ---------------------------------------------------------------------------
# Byte-level encrypt / decrypt
# ---------------------------------------------------------------------------
def encrypt_byte(plain, xor_key):
    b = nibble_encrypt(plain)      # Step 1
    b ^= xor_key                   # Step 2
    b = rotate_right_1(b)          # Step 3
    b = bit_pair_swap(b)           # Step 4
    return b


def decrypt_byte_candidates(cipher, xor_key):
    b = bit_pair_swap(cipher)      # Undo Step 4
    b = rotate_left_1(b)           # Undo Step 3
    b ^= xor_key                   # Undo Step 2
    return nibble_decrypt_candidates(b)  # Undo Step 1 → 16 candidates


# ---------------------------------------------------------------------------
# Buffer-level encrypt / decrypt
# ---------------------------------------------------------------------------
def encrypt_buffer(data, pwd_hash):
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        out[i] = encrypt_byte(byte, xor_key_for_index(pwd_hash, i))
    return bytes(out)


def decrypt_buffer(data, pwd_hash, hint_first_byte=-1):
    """
    Decrypt data.  For each byte, candidate[0] (high_nibble=0) is chosen.
    If hint_first_byte >= 0, it is used to pick the correct candidate for
    byte 0 (useful when the plaintext magic byte is known).
    """
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        key = xor_key_for_index(pwd_hash, i)
        cands = decrypt_byte_candidates(byte, key)
        if not cands:
            out[i] = 0x00
            continue
        if i == 0 and hint_first_byte >= 0:
            match = [c for c in cands if c == hint_first_byte]
            out[i] = match[0] if match else cands[0]
        else:
            out[i] = cands[0]
    return bytes(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def usage():
    print(__doc__)
    sys.exit(1)


def main():
    if len(sys.argv) < 5:
        usage()

    mode      = sys.argv[1].lower()
    in_path   = sys.argv[2]
    out_path  = sys.argv[3]
    password  = sys.argv[4]
    hint      = -1

    if "--hint" in sys.argv:
        idx = sys.argv.index("--hint")
        try:
            hint = int(sys.argv[idx + 1], 16)
        except (IndexError, ValueError):
            print("ERROR: --hint requires a hex byte, e.g. --hint FF")
            sys.exit(1)

    try:
        with open(in_path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"ERROR reading input: {e}")
        sys.exit(1)

    pwd_hash = hash_password(password)

    if mode == "encrypt":
        result = encrypt_buffer(data, pwd_hash)
        label = "Encrypted"
    elif mode == "decrypt":
        result = decrypt_buffer(data, pwd_hash, hint)
        label = "Decrypted"
    else:
        print(f"ERROR: unknown mode '{mode}' — use 'encrypt' or 'decrypt'")
        usage()

    try:
        with open(out_path, "wb") as f:
            f.write(result)
    except OSError as e:
        print(f"ERROR writing output: {e}")
        sys.exit(1)

    print(f"{label} {len(result)} bytes  →  {out_path}")


if __name__ == "__main__":
    main()
