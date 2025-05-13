#  Ransomware Skeleton (Educational Purpose Only)

>  **Disclaimer**: This project is a *research-grade, educational skeleton* of a ransomware-like file encryptor/decryptor built in C.

> It is **not** intended for illegal use or deployment. This code is meant for **academic learning, malware analysis, or security testing** in safe environments.

> It most likely work only on Linux

---

##  Overview

This repository contains a C-based prototype that mimics the *behavioral structure* of ransomware:  
- It encrypts entire directories recursively using **XChaCha20-Poly1305** (via [libsodium](https://libsodium.gitbook.io/doc/)).
- Keys and metadata are stored for controlled decryption.
- It can be adapted for studying malware behaviors, anti-virus evasion, or cryptographic performance.

---

##  Features

-  Strong encryption using `crypto_secretstream_xchacha20poly1305`
-  Full-directory recursive processing
-  Per-directory encryption keys stored centrally
-  Ideal for controlled lab environments and simulations

---

##  Build Instructions

Install [libsodium](https://libsodium.gitbook.io/doc/installation) first, then:

```bash
make
```

---

## Usage

Simply run the binary like so

```bash
./ransonware
```

- Encrypted keys and headers are stored in the special file /table

- Decryption uses the data in /table to restore files

---

## Design Philosophy

This tool mimics the logic and structure of real ransomware:

- Encrypts files in-place with per-directory keys.

- Maintains mapping between keys and paths via a master key file (/table).

- Clean recursive traversal using POSIX-compliant functions.

---

## LEGAL WARNING

**This software is provided strictly for educational purposes.
Do not use it to target systems you don’t own or have explicit permission to analyze.**

---

## Final Notes

- Do not run this on live or personal systems.

- Always test in a virtual machine or isolated lab environment.

- Treat this tool with the same caution you'd apply to real malware
