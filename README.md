# 🔐 Cryptography Lab - C++ Implementations

Welcome to the **Cryptography Lab** repository. This collection includes hands-on labs for symmetric and asymmetric cryptographic algorithms, implemented primarily in **C++**, using both built-in and external libraries like **Crypto++**.

## 📁 Lab Structure

Each lab is contained in its own folder with a dedicated `README.md` explaining the functionality, compilation instructions, and usage.

| Lab | Folder | Description |
|-----|--------|-------------|
| Lab 1 | `lab1_des_aes_cryptopp` | DES & AES using Crypto++ with multiple modes (ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM) |
| Lab 2 | `aes_pure_cpp_cbc_mode` | AES encryption in CBC mode using **only C++**, no external libraries |
| Lab 3 | `rsa_oaep_cryptopp` | RSA Encryption/Decryption with OAEP padding using Crypto++ |
| ... | `labX_name` | More labs to be added as the course progresses |

> ✅ Each lab supports **UTF-8** for Vietnamese plaintext input/output.

## 🧪 Features Across Labs

- Symmetric Encryption (DES, AES)
- Asymmetric Encryption (RSA-OAEP)
- Key generation and key file management
- Command-line and file-based I/O
- Performance testing on Linux & Windows
- Support for exporting `.dll` (Windows) or `.so` (Linux) libraries

## 🛠 Requirements

- C++17 or later
- [Crypto++ Library](https://www.cryptopp.com/) (for specific labs)
- Compilers: `g++`, `clang++`, `cl` (MSVC)
- Optional: Git, Make, Shell/Bash

---

## 📚 License
This repository is for educational purposes only. All rights reserved © 2025.

>"Understanding cryptography through code is the best way to learn how security really works." 🔐