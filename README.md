# SecureFile - 安全文件加密工具

[English Version Below](#english-version)

## 概述

SecureFile 是一个高级文件安全工具，它将您的敏感文件加密并伪装成真正的HEVC视频文件。这款工具结合了军事级加密技术与创新的视频伪装技术，为您的数据提供多重保护：

- 🔒 **强加密**：使用AES-GCM和ChaCha20-Poly1305等认证加密算法
- 🎥 **完美伪装**：生成完全有效的HEVC视频文件
- 🛡️ **完整性保护**：HMAC-SHA256验证防止数据篡改
- 🔑 **密钥安全**：每个数据块使用唯一派生密钥
- 🧹 **安全擦除**：内存中的敏感数据会被彻底清除

## 安全特性

1. **双算法加密**：
   - 随机选择AES-GCM或ChaCha20-Poly1305算法
   - 每个数据块使用唯一加密密钥
   - 256位主密钥保护

2. **密钥派生系统**：
   - Scrypt密钥派生函数（n=2²⁰, r=32）
   - 抗暴力破解设计
   - 主密钥与HMAC密钥分离

3. **完整性验证**：
   - 每个加密块使用HMAC-SHA256签名
   - 元数据完整性和认证保护
   - 防止数据篡改和重放攻击

4. **内存安全**：
   - 敏感数据多重覆盖清除
   - 防内存泄露设计
   - 恒定时间比较防止时序攻击

## 安装与使用

### 系统要求
- Python 3.7+
- FFmpeg（用于视频编解码）
- 加密库：`cryptography`

### 安装步骤
1. 安装依赖库：
```bash
pip install cryptography
```

2. 安装FFmpeg：
- Windows: [下载链接](https://www.gyan.dev/ffmpeg/builds/)
- macOS: `brew install ffmpeg`
- Linux: `sudo apt install ffmpeg`

3. 运行程序：
```bash
python SecureFile.py
```

### 使用指南

**加密文件夹**：
1. 选择要加密的文件夹
2. 设置强密码（可选但推荐）
3. 选择输出目录
4. 点击"开始加密"
5. 程序将生成：
   - 多个HEVC视频文件（.mp4）
   - 加密元数据文件（encryption_metadata.enc）

**解密文件**：
1. 选择所有相关视频文件
2. 选择元数据文件
3. 输入加密时使用的密码
4. 选择输出目录
5. 点击"开始解密"

## 技术细节

### 加密流程
1. 文件夹压缩为ZIP（最高压缩级别）
2. ZIP文件分割为随机大小的数据块（≤20MB）
3. 每个数据块：
   - 随机选择加密算法
   - 使用唯一派生密钥加密
   - 添加HMAC完整性签名
4. 加密数据转换为真正的HEVC视频
5. 加密元数据存储所有必要信息

### 解密流程
1. 从视频中提取加密数据
2. 验证每个块的HMAC签名
3. 使用派生密钥解密每个块
4. 重组为原始ZIP文件
5. 解压恢复原始文件夹结构

## 注意事项

1. **密码安全**：
   - 使用12位以上复杂密码
   - 包含大小写字母、数字和特殊符号
   - 密码丢失将无法恢复数据

2. **文件管理**：
   - 安全保存元数据文件
   - 保留所有生成的视频文件
   - 解密时需要所有视频文件和元数据

3. **性能考虑**：
   - 大文件处理需要时间
   - 视频转换消耗CPU资源
   - 确保足够磁盘空间

## 免责声明

本工具仅用于合法目的。开发者不对以下情况负责：
- 用户丢失加密密钥导致数据无法恢复
- 非法使用本工具造成的后果
- 因硬件故障或操作失误导致的数据丢失

使用本工具即表示您同意自行承担所有风险。

## 许可证

本项目采用 GPLv3 许可证 - 详见 [LICENSE](LICENSE) 文件。

---

<a name="english-version"></a>
# SecureFile - Secure File Encryption Tool

## Overview

SecureFile is an advanced file security tool that encrypts your sensitive files and disguises them as genuine HEVC video files. This application combines military-grade encryption with innovative video steganography techniques to provide multi-layered protection for your data:

- 🔒 **Strong Encryption**: Uses authenticated encryption algorithms like AES-GCM and ChaCha20-Poly1305
- 🎥 **Perfect Camouflage**: Generates fully valid HEVC video files
- 🛡️ **Integrity Protection**: HMAC-SHA256 verification prevents data tampering
- 🔑 **Key Security**: Unique derived key for each data chunk
- 🧹 **Secure Erasure**: Sensitive data in memory is thoroughly wiped

## Security Features

1. **Dual-Algorithm Encryption**:
   - Random selection between AES-GCM or ChaCha20-Poly1305
   - Unique encryption key for each data chunk
   - 256-bit master key protection

2. **Key Derivation System**:
   - Scrypt key derivation function (n=2²⁰, r=32)
   - Brute-force resistance design
   - Separation of master key and HMAC key

3. **Integrity Verification**:
   - HMAC-SHA256 signature for each encrypted chunk
   - Metadata integrity and authentication protection
   - Prevention against data tampering and replay attacks

4. **Memory Security**:
   - Multi-pass overwrite of sensitive data
   - Memory leak prevention design
   - Constant-time comparison to prevent timing attacks

## Installation & Usage

### System Requirements
- Python 3.7+
- FFmpeg (for video encoding/decoding)
- Cryptography library: `cryptography`

### Installation Steps
1. Install dependencies:
```bash
pip install cryptography
```

2. Install FFmpeg:
- Windows: [Download](https://www.gyan.dev/ffmpeg/builds/)
- macOS: `brew install ffmpeg`
- Linux: `sudo apt install ffmpeg`

3. Run the application:
```bash
python SecureFile.py
```

### User Guide

**Encrypting a Folder**:
1. Select the folder to encrypt
2. Set a strong password (optional but recommended)
3. Choose output directory
4. Click "Start Encryption"
5. The program will generate:
   - Multiple HEVC video files (.mp4)
   - Encryption metadata file (encryption_metadata.enc)

**Decrypting Files**:
1. Select all related video files
2. Choose the metadata file
3. Enter the password used during encryption
4. Select output directory
5. Click "Start Decryption"

## Technical Details

### Encryption Process
1. Folder compression to ZIP (maximum compression level)
2. ZIP file split into random-sized chunks (≤20MB)
3. For each chunk:
   - Random encryption algorithm selection
   - Encryption with unique derived key
   - HMAC integrity signature added
4. Encrypted data converted to genuine HEVC video
5. Encrypted metadata stores all necessary information

### Decryption Process
1. Extract encrypted data from videos
2. Verify HMAC signature for each chunk
3. Decrypt each chunk using derived keys
4. Reassemble into original ZIP file
5. Extract to restore original folder structure

## Important Notes

1. **Password Security**:
   - Use complex passwords (12+ characters)
   - Include uppercase, lowercase, numbers, and symbols
   - Data recovery impossible if password is lost

2. **File Management**:
   - Securely store metadata files
   - Preserve all generated video files
   - All video files and metadata required for decryption

3. **Performance Considerations**:
   - Large files require significant processing time
   - Video conversion is CPU-intensive
   - Ensure sufficient disk space

## Disclaimer

This tool is intended for legal purposes only. The developers are not responsible for:
- Data loss due to lost encryption keys
- Consequences of illegal use of this tool
- Data loss caused by hardware failure or user error

By using this tool, you agree to assume all risks associated with its use.

## License

This project is under the GPLv3 license - see [LICENSE](LICENSE) document for details.
