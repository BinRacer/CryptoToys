<div align="center">
  <a href="https://github.com/BinRacer/CryptoToys">
    <img src="images/banner.zh-CN.svg" alt="CryptoToys" style="width:100%; max-width:100%; margin-top:0; margin-bottom:-0.5rem">
  </a>
  
  <div style="margin-top:-3rem; line-height:1; padding:0">
    <img src="https://img.shields.io/badge/Platform-Windows-blue" alt="Platform">
    <img src="https://img.shields.io/badge/C++-17-purple" alt="C++17">
    <img src="https://img.shields.io/badge/Qt-6.9.1-purple" alt="Qt">
    <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT">
  </div>
</div>  
<div align="center">

[English](./README.md) | 简体中文

</div>

---

### 🚀 CryptoToys - 基于YanLib的加密工具集

**CryptoToys** 是一款基于 **YanLib** 的在线加密解密工具集，通过Qt实现图形化界面，提供直观的加密操作体验。

#### 🌟 核心优势
- **高效安全**：基于C++ RAII实现资源自动管理
- **界面友好**：Qt图形化界面简化复杂加密操作
- **模块化设计**：四大功能模块满足不同加密需求

---

### 🧩 功能模块

| 类别              | 算法列表                                                                 |
|-------------------|--------------------------------------------------------------------------|
| **Base编解码**    | base16, base32, base58, base62, base64, base85, base91, base92, base100 |
| **简单加密**      | uuencode, xxencode, vigenere                                            |
| **高级加密**      | AES, RSA                                                                 |
| **Hash编码**      | md5, sha1, sha256, sha384, sha512                                        |

---

### 🖼️ 界面预览

#### 主界面
![主界面](images/main.png)

#### RSA加密示例
![RSA加密](images/rsa_encode.png)

#### RSA解密示例
![RSA解密](images/rsa_decode.png)

---

### ⚠️ 注意事项
1. **依赖库**：YanLib.lib需从[YanLib项目Release](https://github.com/BinRacer/YanLib/releases)单独下载
2. **项目结构**：仅包含头文件，不包含完整库文件

---

### 📜 版权声明
```plaintext
本产品包含Qt库，Copyright © The Qt Company Ltd.，遵循LGPLv3协议。
Qt是The Qt Company Ltd的注册商标。
本程序动态链接Qt库，未修改其源代码。
