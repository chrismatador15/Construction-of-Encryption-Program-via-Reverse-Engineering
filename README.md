# Construction-of-Encryption-Program-via-Reverse-Engineering
## CS 4653 - Reverse Engineering

## Overview
This project was developed through static and dynamic reverse engineering 
techniques. By analyzing a PE binary in IDA Pro, we identified and 
reconstructed a custom multi-step per-byte cipher pipeline. The result 
is a working encryptor built in Python that encrypts a file which can 
then be fully restored using the provided Decrypt.exe.

Verified on: `.txt`, `.docx`, and `.mp4` file types.


## Usage

python encrypt_11.py encrypt <input_file> <output_file> <password>

python encrypt_11.py encrypt hello.txt hello.enc 1111

Password is optional. Output format:

encrypt: X bytes -> Y bytes -> encrypted_picture/encrypted_file

Where `X bytes` is the original file size and `Y bytes` is the 
size after encryption


## Cipher Pipeline
The core per-byte transform was identified at `sub_412850` in IDA Pro, 
chaining four sub-functions:

| Step | Function | Operation |
|------|----------|-----------|
| 1 | `step1(b)` | Nibble swap — swaps high and low 4 bits via `((b<<4) + (b>>4)) & 0xFF` |
| 2 | XOR | Input XORed against an 8-entry lookup table keyed by `idx & 4` |
| 3 | `rot_r` / `rot_l` | Single-bit rotation left (encrypt) or right (decrypt) |
| 4 | `step4(b)` | Bit-pair permutation — rearranges bits by pattern `[4,5,0,1,6,7,2,3]` |

---

## Key Findings
- **Dead code in Step 4:** IDA decompiler showed a table XOR stored in 
  `var_E`, but the return instruction loaded from `var_D` (pre-XOR), 
  making the table XOR entirely dead code. Removing it from the Python 
  implementation produced correct output immediately.
- **File format:** The binary makes two `fread` calls — one at the start 
  and one 16 bytes from the end — storing a 16-byte key in plaintext at 
  both ends of the file.
- **Cipher direction:** `sub_412850` is the *decrypt* operation. The 
  encryptor applies the inverse of each step in reverse order to produce 
  output that Decrypt.exe can correctly restore.

---

## Tools Used
- IDA Pro — static analysis and control flow tracing
- WinDbg — dynamic analysis
- HxD — hex-level file inspection
- Python + PyInstaller — reconstruction and packaging

---

## Files Tested
| File Type | Result |
|-----------|--------|
| `.txt` | Decrypted content matched original exactly |
| `.docx` | Restored correctly in Microsoft Word |
| `.mp4` | Full video recovered after decryption |
