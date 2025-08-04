<div align="center">
  <a href="https://github.com/BinRacer/CryptoToys">
    <img src="images/banner.svg" alt="CryptoToys" style="width:100%; max-width:100%; margin-top:0; margin-bottom:-0.5rem">
  </a>
  
  <div style="margin-top:-3rem; line-height:1; padding:0">
    <img src="https://img.shields.io/badge/Platform-Windows-blue" alt="Platform">
    <img src="https://img.shields.io/badge/C++-17-purple" alt="C++17">
    <img src="https://img.shields.io/badge/Qt-6.9.1-purple" alt="Qt">
    <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT">
  </div>
</div>  
<div align="center">

English | [简体中文](./README.zh-CN.md)

</div>

---

### 🚀 CryptoToys - Crypto Toolkit Built on YanLib  

**CryptoToys** is an encryption/decryption toolkit with a Qt-based graphical interface, delivering an intuitive cryptographic experience through its visual design.

#### 🌟 Core Advantages  
- **Efficiency & Security**: Implements automated resource management via C++ RAII  
- **User-Friendly**: Simplifies complex operations through Qt's visual interface  
- **Modular Architecture**: Four functional modules to address diverse cryptographic needs  

---

### 🧩 Feature Modules  

| Category          | Algorithms                                                                 |
|-------------------|----------------------------------------------------------------------------|
| **Base Encode/Decode** | base16, base32, base58, base62, base64, base85, base91, base92, base100 |
| **Simple Ciphers**     | uuencode, xxencode, vigenere                                              |
| **Advanced Encryption**| AES, RSA                                                                   |
| **Hash Algorithms**    | md5, sha1, sha256, sha384, sha512                                          |

---

### 🖼️ UI Preview  

#### Main Interface  
![Main Interface](images/main.png)

#### RSA Encryption Demo  
![RSA Encryption](images/rsa_encode.png) 

#### RSA Decryption Demo  
![RSA Decryption](images/rsa_decode.png)

---

### ⚠️ Usage Notes  
1. **Dependencies**: YanLib.lib must be downloaded separately from https://github.com/BinRicer/YanLib/releases  
2. **Project Structure**: Includes header files only, not full library binaries  

---

### 📜 Copyright Notice  
```plaintext
This product includes Qt libraries, Copyright © The Qt Company Ltd., licensed under LGPLv3.  
Qt is a registered trademark of The Qt Company Ltd.  
This application dynamically links to Qt libraries without modifying their source code.  
```
