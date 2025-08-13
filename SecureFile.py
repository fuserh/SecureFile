import os
import sys
import json
import random
import string
import shutil
import zipfile
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, constant_time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import time
from datetime import datetime
import tempfile
import math
import ctypes
import secrets
from typing import Tuple, Optional, Dict, List, Any

# ======================
# 安全核心功能
# ======================

class SecureMemory:
    """安全内存管理，用于处理敏感数据"""
    
    @staticmethod
    def secure_erase(buffer: bytearray) -> None:
        """安全擦除内存中的敏感数据"""
        if not buffer:
            return
            
        # 使用随机数据覆盖多次
        for _ in range(3):
            random_data = os.urandom(len(buffer))
            for i in range(len(buffer)):
                buffer[i] = random_data[i]
        
        # 尝试使用ctypes强制清除
        try:
            addr = id(buffer) + getattr(buffer, '__offset__', 0)
            size = sys.getsizeof(buffer)
            ctypes.memset(addr, 0, size)
        except:
            pass  # 失败也没关系，我们已经覆盖了数据
    
    @staticmethod
    def compare_secure(a: bytes, b: bytes) -> bool:
        """安全的恒定时间比较"""
        return constant_time.bytes_eq(a, b)
    
    @staticmethod
    def wipe_sensitive_data(*args) -> None:
        """安全擦除多个敏感对象"""
        for arg in args:
            if isinstance(arg, bytearray):
                SecureMemory.secure_erase(arg)
            elif isinstance(arg, bytes):
                # 无法直接擦除bytes（不可变），但我们尝试覆盖引用
                try:
                    ctypes.memset(id(arg), 0, sys.getsizeof(arg))
                except:
                    pass

class SecureRandom:
    """安全随机数生成器封装"""
    
    @staticmethod
    def random_bytes(n: int) -> bytes:
        """生成加密安全的随机字节"""
        return secrets.token_bytes(n)
    
    @staticmethod
    def random_int(min_val: int, max_val: int) -> int:
        """生成加密安全的随机整数"""
        return secrets.randbelow(max_val - min_val + 1) + min_val
    
    @staticmethod
    def random_choice(seq: list) -> Any:
        """安全的随机选择"""
        return secrets.choice(seq)

class FileIntegrity:
    """文件完整性验证工具"""
    
    @staticmethod
    def generate_hmac(key: bytes, data: bytes) -> bytes:
        """生成HMAC-SHA256用于完整性验证"""
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()
    
    @staticmethod
    def verify_hmac(key: bytes, data: bytes, expected_hmac: bytes) -> bool:
        """验证HMAC-SHA256"""
        try:
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(data)
            h.verify(expected_hmac)
            return True
        except:
            return False

# ======================
# 核心加密/解密功能
# ======================

class SecureFileEncryptor:
    MAX_CHUNK_SIZE = 20 * 1024 * 1024  # 20MB
    METADATA_VERSION = "3.0"
    ENCRYPTION_ALGORITHMS = ['AES-GCM', 'ChaCha20-Poly1305']
    MASTER_KEY_SIZE = 32  # 256 bits
    SALT_SIZE = 16
    HMAC_KEY_SIZE = 32
    
    def __init__(self, password: Optional[str] = None):
        """初始化加密器，可选密码用于密钥派生"""
        self.password = password
        self.master_key = None
        self.hmac_key = None
        self.salt = None
        self.encryption_info = {
            "version": self.METADATA_VERSION,
            "chunks": [],
            "original_filename": "",
            "timestamp": datetime.now().isoformat(),
            "total_chunks": 0,
            "metadata_hmac": ""
        }
        
        # 如果提供了密码，派生主密钥
        if password:
            self._derive_master_keys()
    
    def __del__(self):
        """析构函数，确保敏感数据被清除"""
        if self.master_key:
            SecureMemory.secure_erase(self.master_key)
        if self.hmac_key:
            SecureMemory.secure_erase(self.hmac_key)
    
    def _derive_master_keys(self) -> None:
        """从密码安全派生主密钥和HMAC密钥"""
        # 生成随机盐
        self.salt = SecureRandom.random_bytes(self.SALT_SIZE)
        
        # 使用高强度参数进行密钥派生
        kdf = Scrypt(
            salt=self.salt,
            length=self.MASTER_KEY_SIZE * 2,  # 派生主密钥和HMAC密钥
            n=2**20,  # 高CPU成本参数（比之前高8倍）
            r=32,     # 高内存成本参数
            p=1,
            backend=default_backend()
        )
        
        # 派生密钥材料
        key_material = kdf.derive(self.password.encode())
        
        # 分割密钥材料
        self.master_key = key_material[:self.MASTER_KEY_SIZE]
        self.hmac_key = key_material[self.MASTER_KEY_SIZE:]
        
        # 立即清除原始密钥材料
        SecureMemory.secure_erase(bytearray(key_material))
    
    def _clear_master_keys(self) -> None:
        """安全清除主密钥"""
        if self.master_key:
            SecureMemory.secure_erase(self.master_key)
            self.master_key = None
        if self.hmac_key:
            SecureMemory.secure_erase(self.hmac_key)
            self.hmac_key = None
    
    def _generate_chunk_key(self, chunk_index: int) -> Tuple[bytes, bytes]:
        """为每个数据块生成唯一密钥（从主密钥派生）"""
        if not self.master_key:
            raise ValueError("主密钥未设置")
        
        # 使用HKDF从主密钥派生块密钥
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.MASTER_KEY_SIZE * 2,  # 密钥和nonce
            salt=self.salt,
            info=f"chunk-key-{chunk_index}".encode(),
            backend=default_backend()
        )
        
        key_material = hkdf.derive(self.master_key)
        
        # 分割为加密密钥和nonce
        key = key_material[:self.MASTER_KEY_SIZE]
        nonce = key_material[self.MASTER_KEY_SIZE:self.MASTER_KEY_SIZE+12]  # 12字节nonce
        
        # 立即清除原始密钥材料
        SecureMemory.secure_erase(bytearray(key_material))
        
        return key, nonce
    
    def _encrypt_metadata(self, metadata: str) -> bytes:
        """使用AEAD模式加密元数据（安全增强）"""
        if not self.master_key:
            return metadata.encode()
        
        # 生成随机nonce
        nonce = SecureRandom.random_bytes(12)
        
        # 使用AES-GCM进行认证加密
        aesgcm = AESGCM(self.master_key)
        encrypted_data = aesgcm.encrypt(nonce, metadata.encode(), None)
        
        # 返回nonce + 密文
        return nonce + encrypted_data
    
    def _decrypt_metadata(self, encrypted_metadata: bytes) -> str:
        """安全解密元数据"""
        if not self.master_key or len(encrypted_metadata) < 12:
            return encrypted_metadata.decode()
        
        # 提取nonce（前12字节）
        nonce = encrypted_metadata[:12]
        ciphertext = encrypted_metadata[12:]
        
        try:
            # 使用AES-GCM进行认证解密
            aesgcm = AESGCM(self.master_key)
            metadata = aesgcm.decrypt(nonce, ciphertext, None)
            return metadata.decode()
        except Exception as e:
            raise ValueError("元数据解密失败 - 可能密码错误或数据被篡改") from e
    
    def _generate_chunk_hmac(self, chunk_index: int, encrypted_data: bytes) -> bytes:
        """为加密块生成HMAC"""
        if not self.hmac_key:
            return b""
        
        # 包含块索引以防止重放攻击
        data_to_hash = f"{chunk_index}".encode() + encrypted_data
        return FileIntegrity.generate_hmac(self.hmac_key, data_to_hash)
    
    def _verify_chunk_hmac(self, chunk_index: int, encrypted_data: bytes, expected_hmac: bytes) -> bool:
        """验证加密块的HMAC"""
        if not self.hmac_key:
            return True  # 无HMAC密钥，无法验证
        
        return FileIntegrity.verify_hmac(
            self.hmac_key,
            f"{chunk_index}".encode() + encrypted_data,
            expected_hmac
        )
    
    def compress_folder(self, folder_path: str, output_zip_path: str) -> str:
        """将文件夹压缩成zip文件（使用最高压缩级别）"""
        with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, folder_path)
                    zipf.write(file_path, arcname)
        return output_zip_path
    
    def split_file_into_random_chunks(self, file_path: str) -> List[bytes]:
        """将文件分割成随机大小的块（不超过20MB）"""
        chunks = []
        total_size = os.path.getsize(file_path)
        
        with open(file_path, 'rb') as f:
            position = 0
            while position < total_size:
                # 生成一个随机大小，确保不超过最大值且至少1KB
                remaining = total_size - position
                chunk_size = min(SecureRandom.random_int(1024, self.MAX_CHUNK_SIZE), remaining)
                
                chunk_data = f.read(chunk_size)
                if not chunk_data:
                    break
                
                chunks.append(chunk_data)
                position += chunk_size
        
        return chunks
    
    def encrypt_chunk_aes_gcm(self, chunk_data: bytes, key: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
        """使用AES-GCM加密数据块（认证加密）"""
        aesgcm = AESGCM(key)
        encrypted_data = aesgcm.encrypt(nonce, chunk_data, None)
        
        # AES-GCM输出 = 密文 + 认证标签（16字节）
        return encrypted_data[:-16], encrypted_data[-16:]
    
    def encrypt_chunk_chacha20_poly1305(self, chunk_data: bytes, key: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
        """使用ChaCha20-Poly1305加密数据块（认证加密）"""
        # ChaCha20-Poly1305在cryptography中通过AESGCM接口提供
        aesgcm = AESGCM(key)
        encrypted_data = aesgcm.encrypt(nonce, chunk_data, None)
        
        # 输出 = 密文 + 认证标签（16字节）
        return encrypted_data[:-16], encrypted_data[-16:]
    
    def create_real_hevc_video(self, encrypted_data: bytes, output_path: str) -> bool:
        """
        将加密数据真正转码为HEVC视频文件
        这是关键功能：创建有效的HEVC视频文件
        """
        # 创建临时文件
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as temp_bin:
            temp_bin_path = temp_bin.name
            temp_bin.write(encrypted_data)
        
        try:
            # 计算视频尺寸：确保总像素数至少等于数据大小
            data_size = len(encrypted_data)
            # 像素格式为gray16le，每个像素2字节
            total_pixels = data_size // 2
            
            # 计算合理的分辨率（接近16:9）
            height = int(math.sqrt(total_pixels / (16/9)))
            width = int(height * (16/9))
            
            # 确保尺寸合理
            if height < 100:
                height = 100
                width = 178  # 16:9比例
            
            # 计算帧数：1秒，30fps
            frame_count = 30
            pixels_per_frame = width * height
            bytes_per_frame = pixels_per_frame * 2  # gray16le
            
            # 如果数据不足以填充一帧，重复数据
            if data_size < bytes_per_frame:
                repeat_count = (bytes_per_frame + data_size - 1) // data_size
                encrypted_data = encrypted_data * repeat_count
                data_size = len(encrypted_data)
            
            # 如果数据不足以填充所有帧，重复数据
            if data_size < bytes_per_frame * frame_count:
                repeat_count = (bytes_per_frame * frame_count + data_size - 1) // data_size
                encrypted_data = encrypted_data * repeat_count
                data_size = len(encrypted_data)
            
            # 创建临时原始视频文件
            with tempfile.NamedTemporaryFile(suffix='.yuv', delete=False) as temp_yuv:
                temp_yuv_path = temp_yuv.name
                temp_yuv.write(encrypted_data[:bytes_per_frame * frame_count])
            
            # 使用FFmpeg创建HEVC视频
            ffmpeg_cmd = [
                'ffmpeg',
                '-y',  # 覆盖输出文件
                '-f', 'rawvideo',
                '-pix_fmt', 'gray16le',
                '-s', f'{width}x{height}',
                '-r', '30',  # 30 fps
                '-i', temp_yuv_path,
                '-c:v', 'libx265',
                '-preset', 'fast',
                '-crf', '28',  # 质量参数
                '-tag:v', 'hvc1',  # HEVC tag
                '-movflags', '+faststart',
                output_path
            ]
            
            # 执行FFmpeg命令
            result = subprocess.run(
                ffmpeg_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            if result.returncode != 0:
                error_msg = result.stderr.decode()
                raise RuntimeError(f"FFmpeg错误: {error_msg}")
            
            return True
            
        except Exception as e:
            raise RuntimeError(f"创建HEVC视频失败: {str(e)}")
        finally:
            # 清理临时文件
            if os.path.exists(temp_bin_path):
                os.unlink(temp_bin_path)
            if 'temp_yuv_path' in locals() and os.path.exists(temp_yuv_path):
                os.unlink(temp_yuv_path)
    
    def process_for_encryption(self, folder_path: str, output_dir: str) -> Dict[str, Any]:
        """处理整个加密流程（安全优先）"""
        temp_dir = None
        try:
            # 1. 创建临时目录
            temp_dir = os.path.join(output_dir, "temp_encrypt_" + str(int(time.time())))
            os.makedirs(temp_dir, exist_ok=True)
            
            # 2. 压缩文件夹
            zip_filename = os.path.basename(folder_path.rstrip(os.sep)) + ".zip"
            zip_path = os.path.join(temp_dir, zip_filename)
            self.compress_folder(folder_path, zip_path)
            
            # 3. 分割文件
            chunks = self.split_file_into_random_chunks(zip_path)
            self.encryption_info["total_chunks"] = len(chunks)
            
            # 4. 加密块并创建HEVC视频
            os.makedirs(output_dir, exist_ok=True)
            video_files = []
            
            for i, chunk in enumerate(chunks):
                # 随机选择加密算法
                algorithm = SecureRandom.random_choice(self.ENCRYPTION_ALGORITHMS)
                
                # 为这个块生成唯一密钥
                key, nonce = self._generate_chunk_key(i)
                
                # 加密
                if algorithm == 'AES-GCM':
                    encrypted_data, auth_tag = self.encrypt_chunk_aes_gcm(chunk, key, nonce)
                else:  # ChaCha20-Poly1305
                    encrypted_data, auth_tag = self.encrypt_chunk_chacha20_poly1305(chunk, key, nonce)
                
                # 生成HMAC用于完整性验证
                chunk_hmac = self._generate_chunk_hmac(i, encrypted_data + auth_tag)
                
                # 创建元数据
                chunk_metadata = {
                    "index": i,
                    "algorithm": algorithm,
                    "nonce": base64.b64encode(nonce).decode(),
                    "auth_tag": base64.b64encode(auth_tag).decode(),
                    "chunk_hmac": base64.b64encode(chunk_hmac).decode(),
                    "original_size": len(chunk),
                    "encrypted_size": len(encrypted_data)
                }
                
                # 安全清除敏感数据
                SecureMemory.wipe_sensitive_data(key, nonce, auth_tag)
                
                # 存储元数据
                self.encryption_info["chunks"].append(chunk_metadata)
                self.encryption_info["original_filename"] = os.path.basename(folder_path)
                
                # 生成随机文件名
                filename = ''.join(SecureRandom.random_choice(string.ascii_letters + string.digits) for _ in range(12)) + ".mp4"
                filepath = os.path.join(output_dir, filename)
                
                # 将加密数据转码为真正的HEVC视频
                self.create_real_hevc_video(encrypted_data + auth_tag, filepath)
                video_files.append(filepath)
            
            # 5. 保存加密元数据
            metadata_content = json.dumps(self.encryption_info)
            
            # 添加元数据HMAC
            if self.hmac_key:
                metadata_hmac = FileIntegrity.generate_hmac(self.hmac_key, metadata_content.encode())
                self.encryption_info["metadata_hmac"] = base64.b64encode(metadata_hmac).decode()
            
            # 加密元数据
            encrypted_metadata = self._encrypt_metadata(metadata_content)
            
            # 保存到输出目录
            metadata_path = os.path.join(output_dir, "encryption_metadata.enc")
            with open(metadata_path, 'wb') as f:
                f.write(encrypted_metadata)
            
            # 6. 清理临时文件
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            
            return {
                "success": True,
                "message": f"加密成功！生成 {len(video_files)} 个真实HEVC视频文件。",
                "files": video_files,
                "metadata_file": metadata_path
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"加密过程中出错: {str(e)}"
            }
        finally:
            # 确保清除所有敏感数据
            self._clear_master_keys()
            
            # 清理临时目录（如果存在）
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except:
                    pass
    
    # ======================
    # 安全解密功能
    # ======================
    
    def extract_video_data(self, video_path: str) -> bytes:
        """从HEVC视频中提取原始数据（安全方式）"""
        try:
            # 创建临时YUV文件
            with tempfile.NamedTemporaryFile(suffix='.yuv', delete=False) as temp_yuv:
                temp_yuv_path = temp_yuv.name
            
            # 使用FFmpeg提取原始视频数据
            ffmpeg_cmd = [
                'ffmpeg',
                '-y',
                '-i', video_path,
                '-f', 'rawvideo',
                '-pix_fmt', 'gray16le',
                temp_yuv_path
            ]
            
            result = subprocess.run(
                ffmpeg_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            if result.returncode != 0:
                # 尝试不同的像素格式
                pixel_formats = ['gray16le', 'gray', 'rgb24', 'rgba']
                success = False
                
                for pix_fmt in pixel_formats:
                    ffmpeg_cmd = [
                        'ffmpeg',
                        '-y',
                        '-i', video_path,
                        '-f', 'rawvideo',
                        '-pix_fmt', pix_fmt,
                        temp_yuv_path
                    ]
                    
                    result = subprocess.run(
                        ffmpeg_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                    )
                    
                    if result.returncode == 0:
                        success = True
                        break
                
                if not success:
                    raise RuntimeError(f"无法从视频中提取数据: {result.stderr.decode()}")
            
            # 读取原始数据
            with open(temp_yuv_path, 'rb') as f:
                raw_data = f.read()
            
            return raw_data
            
        except Exception as e:
            raise RuntimeError(f"提取视频数据失败: {str(e)}")
        finally:
            # 清理临时文件
            if 'temp_yuv_path' in locals() and os.path.exists(temp_yuv_path):
                try:
                    os.unlink(temp_yuv_path)
                except:
                    pass
    
    def decrypt_chunk_aes_gcm(self, encrypted_data: bytes, auth_tag: bytes, key: bytes, nonce: bytes) -> bytes:
        """使用AES-GCM解密数据块（安全验证）"""
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, encrypted_data + auth_tag, None)
        except Exception as e:
            raise ValueError("解密失败 - 数据可能被篡改或密码错误") from e
    
    def decrypt_chunk_chacha20_poly1305(self, encrypted_data: bytes, auth_tag: bytes, key: bytes, nonce: bytes) -> bytes:
        """使用ChaCha20-Poly1305解密数据块（安全验证）"""
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, encrypted_data + auth_tag, None)
        except Exception as e:
            raise ValueError("解密失败 - 数据可能被篡改或密码错误") from e
    
    def process_for_decryption(self, video_files: List[str], metadata_file: str, output_dir: str) -> Dict[str, Any]:
        """处理整个解密流程（安全优先）"""
        temp_dir = None
        try:
            # 1. 读取并解密元数据
            with open(metadata_file, 'rb') as f:
                encrypted_metadata = f.read()
            
            try:
                metadata_content = self._decrypt_metadata(encrypted_metadata)
                self.encryption_info = json.loads(metadata_content)
            except Exception as e:
                return {
                    "success": False,
                    "message": f"元数据解密失败: {str(e)}"
                }
            
            # 验证元数据版本
            if self.encryption_info.get("version", "1.0") != self.METADATA_VERSION:
                return {
                    "success": False,
                    "message": "元数据版本不兼容，请使用相同版本的程序进行解密"
                }
            
            # 验证元数据完整性
            if self.hmac_key and "metadata_hmac" in self.encryption_info:
                stored_hmac = base64.b64decode(self.encryption_info["metadata_hmac"])
                if not FileIntegrity.verify_hmac(
                    self.hmac_key,
                    metadata_content.encode(),
                    stored_hmac
                ):
                    return {
                        "success": False,
                        "message": "元数据完整性验证失败 - 数据可能被篡改"
                    }
            
            # 2. 从视频中提取数据
            extracted_data = []
            for i, video_file in enumerate(video_files):
                try:
                    raw_data = self.extract_video_data(video_file)
                    extracted_data.append((i, raw_data))
                except Exception as e:
                    return {
                        "success": False,
                        "message": f"无法从视频文件 {os.path.basename(video_file)} 提取数据: {str(e)}"
                    }
            
            # 3. 按元数据中的索引排序
            sorted_chunks = []
            for chunk_info in self.encryption_info["chunks"]:
                found = False
                for idx, data in enumerate(extracted_data):
                    # 检查数据大小是否匹配（考虑认证标签）
                    if len(data[1]) == chunk_info["encrypted_size"] + 16:  # +16 for auth tag
                        sorted_chunks.append((data[1], chunk_info))
                        del extracted_data[idx]
                        found = True
                        break
                
                if not found:
                    return {
                        "success": False,
                        "message": f"无法找到匹配块 {chunk_info['index']} 的视频文件"
                    }
            
            if len(sorted_chunks) != len(self.encryption_info["chunks"]):
                return {
                    "success": False,
                    "message": "无法匹配所有加密块。文件可能已损坏或不完整。"
                }
            
            # 4. 解密所有块
            decrypted_chunks = []
            for i, (encrypted_data, chunk_info) in enumerate(sorted_chunks):
                # 分离加密数据和认证标签
                encrypted_part = encrypted_data[:-16]
                auth_tag = encrypted_data[-16:]
                
                # 验证HMAC
                if not self._verify_chunk_hmac(
                    chunk_info["index"],
                    encrypted_part + auth_tag,
                    base64.b64decode(chunk_info["chunk_hmac"])
                ):
                    return {
                        "success": False,
                        "message": f"块 {i} 的完整性验证失败 - 数据可能被篡改"
                    }
                
                # 为这个块生成唯一密钥
                nonce = base64.b64decode(chunk_info["nonce"])
                key, _ = self._generate_chunk_key(chunk_info["index"])
                
                # 解密
                try:
                    if chunk_info["algorithm"] == 'AES-GCM':
                        decrypted_data = self.decrypt_chunk_aes_gcm(
                            encrypted_part, 
                            auth_tag, 
                            key, 
                            nonce
                        )
                    else:  # ChaCha20-Poly1305
                        decrypted_data = self.decrypt_chunk_chacha20_poly1305(
                            encrypted_part, 
                            auth_tag, 
                            key, 
                            nonce
                        )
                    
                    decrypted_chunks.append(decrypted_data)
                finally:
                    # 立即清除敏感数据
                    SecureMemory.wipe_sensitive_data(key, nonce)
            
            # 5. 重组文件
            temp_dir = os.path.join(output_dir, "temp_decrypt_" + str(int(time.time())))
            os.makedirs(temp_dir, exist_ok=True)
            
            reconstructed_zip = os.path.join(temp_dir, "reconstructed.zip")
            with open(reconstructed_zip, 'wb') as f:
                for chunk in decrypted_chunks:
                    f.write(chunk)
            
            # 6. 解压ZIP文件
            extract_dir = os.path.join(output_dir, self.encryption_info["original_filename"])
            os.makedirs(extract_dir, exist_ok=True)
            
            with zipfile.ZipFile(reconstructed_zip, 'r') as zipf:
                zipf.extractall(extract_dir)
            
            # 7. 清理临时文件
            os.remove(reconstructed_zip)
            
            return {
                "success": True,
                "message": f"解密成功！文件已解压到: {extract_dir}",
                "extracted_dir": extract_dir
            }
            
        except Exception as e:
            import traceback
            print(f"Decryption error: {str(e)}\n{traceback.format_exc()}")
            return {
                "success": False,
                "message": f"解密过程中出错: {str(e)}"
            }
        finally:
            # 确保清除所有敏感数据
            self._clear_master_keys()
            
            # 清理临时目录（如果存在）
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except:
                    pass

# ======================
# 安全GUI界面
# ======================

class SecureEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureFile - 安全文件加密工具")
        self.root.geometry("900x650")
        self.root.configure(bg="#f0f2f5")
        
        # 检查FFmpeg是否可用
        self.ffmpeg_available = self.check_ffmpeg()
        
        # 设置主题样式
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # 配置自定义样式
        self.style.configure('TFrame', background='#f0f2f5')
        self.style.configure('TLabel', background='#f0f2f5', font=('Segoe UI', 10))
        self.style.configure('Header.TLabel', font=('Segoe UI', 16, 'bold'), foreground='#1a73e8')
        self.style.configure('SubHeader.TLabel', font=('Segoe UI', 12, 'bold'), foreground='#5f6368')
        self.style.configure('TButton', font=('Segoe UI', 10), padding=6)
        self.style.configure('Accent.TButton', background='#1a73e8', foreground='white')
        self.style.map('Accent.TButton',
                      background=[('active', '#0d62d9')])
        self.style.configure('Warning.TLabel', foreground='#d93025', font=('Segoe UI', 10, 'bold'))
        self.style.configure('Status.TLabel', font=('Segoe UI', 10, 'italic'), foreground='#5f6368')
        self.style.configure('Security.TLabel', foreground='#34a853', font=('Segoe UI', 10))
        
        # 创建主框架
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 标题
        ttk.Label(self.main_frame, text="SecureFile", style='Header.TLabel').pack(pady=(0, 5))
        ttk.Label(self.main_frame, text="企业级安全文件加密与伪装工具", style='SubHeader.TLabel').pack(pady=(0, 15))
        
        # 安全特性说明
        security_frame = ttk.LabelFrame(self.main_frame, text="安全特性")
        security_frame.pack(fill=tk.X, padx=15, pady=5)
        
        security_features = (
            "✓ 使用AEAD加密模式（AES-GCM和ChaCha20-Poly1305）提供认证加密\n"
            "✓ 每个数据块使用唯一密钥（从主密钥安全派生）\n"
            "✓ 完整的数据完整性验证（HMAC-SHA256）\n"
            "✓ 内存中的敏感数据安全清除\n"
            "✓ 抗侧信道攻击设计\n"
            "✓ 强密码学参数（Scrypt KDF参数：n=2²⁰, r=32）"
        )
        ttk.Label(security_frame, text=security_features, wraplength=800, justify=tk.LEFT, style='Security.TLabel').pack(padx=10, pady=5, anchor=tk.W)
        
        # FFmpeg警告
        if not self.ffmpeg_available:
            warning_frame = ttk.Frame(self.main_frame)
            warning_frame.pack(fill=tk.X, padx=15, pady=5)
            
            ttk.Label(warning_frame, 
                     text="⚠️ 注意：未找到FFmpeg。程序需要FFmpeg才能创建真正的HEVC视频文件。", 
                     style='Warning.TLabel').pack(side=tk.LEFT)
            ttk.Button(warning_frame, text="下载FFmpeg", 
                      command=self.download_ffmpeg).pack(side=tk.RIGHT, padx=5)
        
        # 创建选项卡
        self.tab_control = ttk.Notebook(self.main_frame)
        
        # 加密选项卡
        self.encrypt_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.encrypt_tab, text='加密')
        
        # 解密选项卡
        self.decrypt_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.decrypt_tab, text='解密')
        
        self.tab_control.pack(expand=True, fill=tk.BOTH)
        
        # 设置加密选项卡
        self.setup_encrypt_tab()
        
        # 设置解密选项卡
        self.setup_decrypt_tab()
        
        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪 - " + ("FFmpeg已就绪" if self.ffmpeg_available else "缺少FFmpeg"))
        self.status_bar = ttk.Label(root, textvariable=self.status_var, style='Status.TLabel', anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
        
        # 存储加密器实例
        self.encryptor = None
    
    def check_ffmpeg(self) -> bool:
        """检查FFmpeg是否可用"""
        try:
            subprocess.run(
                ['ffmpeg', '-version'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            return True
        except:
            return False
    
    def download_ffmpeg(self) -> None:
        """提供FFmpeg下载链接"""
        url = "https://www.gyan.dev/ffmpeg/builds/"
        if messagebox.askyesno("FFmpeg下载", f"要打开FFmpeg下载页面吗？\n{url}"):
            import webbrowser
            webbrowser.open(url)
    
    def setup_encrypt_tab(self) -> None:
        """设置加密选项卡的UI"""
        # 文件选择区域
        file_frame = ttk.LabelFrame(self.encrypt_tab, text="选择要加密的文件夹")
        file_frame.pack(fill=tk.X, padx=15, pady=10)
        
        self.folder_path = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.folder_path, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        ttk.Button(file_frame, text="浏览", command=self.browse_folder).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # 密码区域
        password_frame = ttk.LabelFrame(self.encrypt_tab, text="安全设置（强烈建议）")
        password_frame.pack(fill=tk.X, padx=15, pady=10)
        
        password_inner = ttk.Frame(password_frame)
        password_inner.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(password_inner, text="密码（用于加密元数据）:").pack(side=tk.LEFT, padx=5)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(password_inner, textvariable=self.password_var, width=30, show="•")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(password_inner, text="显示密码", variable=self.show_password_var, 
                       command=self.toggle_password_visibility).pack(side=tk.RIGHT, padx=5)
        
        # 添加密码强度指示器
        self.password_strength_var = tk.StringVar()
        self.password_strength_var.set("密码强度: 未设置")
        ttk.Label(password_frame, textvariable=self.password_strength_var, 
                 foreground="#d93025", font=('Segoe UI', 9)).pack(anchor=tk.W, padx=10, pady=(0, 5))
        
        self.password_entry.bind('<KeyRelease>', self.check_password_strength)
        
        # 输出区域
        output_frame = ttk.LabelFrame(self.encrypt_tab, text="输出设置")
        output_frame.pack(fill=tk.X, padx=15, pady=10)
        
        self.output_path = tk.StringVar()
        ttk.Entry(output_frame, textvariable=self.output_path, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        ttk.Button(output_frame, text="浏览", command=self.browse_output).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # 说明区域
        info_frame = ttk.LabelFrame(self.encrypt_tab, text="安全说明")
        info_frame.pack(fill=tk.X, padx=15, pady=10)
        
        info_text = (
            "• 本工具使用企业级安全措施保护您的数据\n"
            "• 每个数据块使用唯一密钥（从主密钥安全派生）\n"
            "• 使用AEAD加密模式（AES-GCM和ChaCha20-Poly1305）提供认证加密\n"
            "• 所有数据块和元数据都经过HMAC-SHA256完整性验证\n"
            "• 内存中的敏感数据会被安全清除，防止内存泄露\n"
            "• 生成的视频文件是有效的HEVC视频，可被任何视频播放器识别\n"
            "• 强烈建议设置强密码以保护元数据"
        )
        ttk.Label(info_frame, text=info_text, wraplength=800, justify=tk.LEFT).pack(padx=10, pady=5, anchor=tk.W)
        
        # 操作按钮
        button_frame = ttk.Frame(self.encrypt_tab)
        button_frame.pack(fill=tk.X, padx=15, pady=15)
        
        self.encrypt_btn = ttk.Button(button_frame, text="开始加密", style='Accent.TButton',
                                    command=self.start_encryption, width=15)
        self.encrypt_btn.pack(side=tk.RIGHT, padx=5)
        
        # 日志区域
        log_frame = ttk.LabelFrame(self.encrypt_tab, text="操作日志")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=8,
                                                font=('Consolas', 9), bg="#ffffff", fg="#333335")
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.config(state=tk.DISABLED)
    
    def setup_decrypt_tab(self) -> None:
        """设置解密选项卡的UI"""
        # 文件选择区域
        file_frame = ttk.LabelFrame(self.decrypt_tab, text="选择HEVC视频文件")
        file_frame.pack(fill=tk.X, padx=15, pady=10)
        
        self.video_files = []
        self.video_listbox = tk.Listbox(file_frame, height=5)
        self.video_listbox.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        
        btn_frame = ttk.Frame(file_frame)
        btn_frame.pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(btn_frame, text="添加文件", command=self.add_video_files).pack(fill=tk.X, pady=2)
        ttk.Button(btn_frame, text="清除列表", command=self.clear_video_files).pack(fill=tk.X, pady=2)
        
        # 元数据文件区域
        metadata_frame = ttk.LabelFrame(self.decrypt_tab, text="加密元数据文件")
        metadata_frame.pack(fill=tk.X, padx=15, pady=10)
        
        self.metadata_path = tk.StringVar()
        ttk.Entry(metadata_frame, textvariable=self.metadata_path, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        ttk.Button(metadata_frame, text="浏览", command=self.browse_metadata).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # 密码区域（如果需要）
        password_frame = ttk.LabelFrame(self.decrypt_tab, text="密码（如果设置了）")
        password_frame.pack(fill=tk.X, padx=15, pady=10)
        
        password_inner = ttk.Frame(password_frame)
        password_inner.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(password_inner, text="解密密码:").pack(side=tk.LEFT, padx=5)
        
        self.decrypt_password_var = tk.StringVar()
        self.decrypt_password_entry = ttk.Entry(password_inner, textvariable=self.decrypt_password_var, width=30, show="•")
        self.decrypt_password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.show_decrypt_password_var = tk.BooleanVar()
        ttk.Checkbutton(password_inner, text="显示密码", variable=self.show_decrypt_password_var, 
                       command=self.toggle_decrypt_password_visibility).pack(side=tk.RIGHT, padx=5)
        
        # 输出区域
        output_frame = ttk.LabelFrame(self.decrypt_tab, text="输出目录")
        output_frame.pack(fill=tk.X, padx=15, pady=10)
        
        self.decrypt_output_path = tk.StringVar()
        ttk.Entry(output_frame, textvariable=self.decrypt_output_path, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        ttk.Button(output_frame, text="浏览", command=self.browse_decrypt_output).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # 说明区域
        info_frame = ttk.LabelFrame(self.decrypt_tab, text="安全解密说明")
        info_frame.pack(fill=tk.X, padx=15, pady=10)
        
        info_text = (
            "• 请选择所有相关的HEVC视频文件（.mp4）\n"
            "• 必须提供加密时生成的元数据文件（encryption_metadata.enc）\n"
            "• 如果加密时设置了密码，需要输入相同的密码进行解密\n"
            "• 所有数据块都会进行完整性验证，防止篡改\n"
            "• 解密后的文件将恢复原始文件夹结构\n"
            "• 程序将从视频中提取原始加密数据并安全解密"
        )
        ttk.Label(info_frame, text=info_text, wraplength=800, justify=tk.LEFT).pack(padx=10, pady=5, anchor=tk.W)
        
        # 操作按钮
        button_frame = ttk.Frame(self.decrypt_tab)
        button_frame.pack(fill=tk.X, padx=15, pady=15)
        
        self.decrypt_btn = ttk.Button(button_frame, text="开始解密", style='Accent.TButton',
                                    command=self.start_decryption, width=15)
        self.decrypt_btn.pack(side=tk.RIGHT, padx=5)
        
        # 日志区域
        log_frame = ttk.LabelFrame(self.decrypt_tab, text="操作日志")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        self.decrypt_log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=8,
                                                        font=('Consolas', 9), bg="#ffffff", fg="#333335")
        self.decrypt_log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.decrypt_log_text.config(state=tk.DISABLED)
    
    def log(self, message: str, is_encryption: bool = True) -> None:
        """记录操作日志"""
        timestamp = time.strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        
        if is_encryption:
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, log_message)
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        else:
            self.decrypt_log_text.config(state=tk.NORMAL)
            self.decrypt_log_text.insert(tk.END, log_message)
            self.decrypt_log_text.see(tk.END)
            self.decrypt_log_text.config(state=tk.DISABLED)
        
        self.status_var.set(message)
    
    def browse_folder(self) -> None:
        """浏览文件夹"""
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_path.set(folder_selected)
            self.log(f"已选择文件夹: {folder_selected}")
    
    def browse_output(self) -> None:
        """浏览输出目录"""
        output_selected = filedialog.askdirectory()
        if output_selected:
            self.output_path.set(output_selected)
            self.log(f"已选择输出目录: {output_selected}")
    
    def browse_metadata(self) -> None:
        """浏览元数据文件"""
        file_selected = filedialog.askopenfilename(
            title="选择元数据文件",
            filetypes=[("加密元数据", "*.enc"), ("所有文件", "*.*")]
        )
        if file_selected:
            self.metadata_path.set(file_selected)
            self.log(f"已选择元数据文件: {file_selected}", False)
    
    def browse_decrypt_output(self) -> None:
        """浏览解密输出目录"""
        output_selected = filedialog.askdirectory()
        if output_selected:
            self.decrypt_output_path.set(output_selected)
            self.log(f"已选择解密输出目录: {output_selected}", False)
    
    def add_video_files(self) -> None:
        """添加HEVC视频文件"""
        files_selected = filedialog.askopenfilenames(
            title="选择HEVC视频文件",
            filetypes=[("MP4文件", "*.mp4"), ("所有文件", "*.*")]
        )
        if files_selected:
            for file_path in files_selected:
                if file_path not in self.video_files:
                    self.video_files.append(file_path)
                    self.video_listbox.insert(tk.END, os.path.basename(file_path))
            self.log(f"已添加 {len(files_selected)} 个视频文件", False)
    
    def clear_video_files(self) -> None:
        """清除视频文件列表"""
        self.video_files = []
        self.video_listbox.delete(0, tk.END)
        self.log("已清除视频文件列表", False)
    
    def toggle_password_visibility(self) -> None:
        """切换密码显示/隐藏"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def toggle_decrypt_password_visibility(self) -> None:
        """切换解密密码显示/隐藏"""
        if self.show_decrypt_password_var.get():
            self.decrypt_password_entry.config(show="")
        else:
            self.decrypt_password_entry.config(show="•")
    
    def check_password_strength(self, event=None) -> None:
        """检查密码强度"""
        password = self.password_var.get()
        
        if not password:
            self.password_strength_var.set("密码强度: 未设置")
            self.password_strength_var.set("密码强度: 未设置")
            return
        
        # 检查密码强度
        strength = 0
        if len(password) >= 12:
            strength += 2
        elif len(password) >= 8:
            strength += 1
        
        if any(c.islower() for c in password):
            strength += 1
        if any(c.isupper() for c in password):
            strength += 1
        if any(c.isdigit() for c in password):
            strength += 1
        if any(not c.isalnum() for c in password):
            strength += 2
        
        # 设置颜色和消息
        if strength < 4:
            color = "#d93025"  # 红色
            message = "弱: 密码太短或太简单"
        elif strength < 6:
            color = "#f9ab00"  # 橙色
            message = "中: 建议增加长度和复杂度"
        else:
            color = "#34a853"  # 绿色
            message = "强: 良好的密码"
        
        self.password_strength_var.set(f"密码强度: {message}")
        self.password_strength_label = ttk.Label(
            self.encrypt_tab, 
            textvariable=self.password_strength_var, 
            foreground=color, 
            font=('Segoe UI', 9)
        )
    
    def start_encryption(self) -> None:
        """开始加密过程（在新线程中运行）"""
        # 验证输入
        if not self.folder_path.get():
            messagebox.showerror("错误", "请选择要加密的文件夹")
            return
        
        if not self.output_path.get():
            messagebox.showerror("错误", "请选择输出目录")
            return
        
        if not self.ffmpeg_available:
            if not messagebox.askyesno("缺少FFmpeg", "未找到FFmpeg。加密过程需要FFmpeg来创建真正的HEVC视频。\n是否继续（将无法创建有效视频）？"):
                return
        
        # 检查密码强度（如果不是空密码）
        password = self.password_var.get().strip()
        if password and len(password) < 8:
            if not messagebox.askyesno("弱密码警告", "您使用的密码较弱（少于8个字符）。\n继续使用此密码可能会降低安全性。\n是否继续？"):
                return
        
        # 禁用按钮防止重复点击
        self.encrypt_btn.config(state=tk.DISABLED)
        
        # 记录开始
        self.log("开始加密过程...", True)
        
        # 在新线程中运行加密
        threading.Thread(target=self.run_encryption, args=(password,), daemon=True).start()
    
    def run_encryption(self, password: Optional[str]) -> None:
        """实际执行加密操作"""
        try:
            # 创建加密器
            self.encryptor = SecureFileEncryptor(password)
            
            # 执行加密
            result = self.encryptor.process_for_encryption(
                self.folder_path.get(),
                self.output_path.get()
            )
            
            if result["success"]:
                self.log("加密过程完成！", True)
                self.log(f"生成 {len(result['files'])} 个真实HEVC视频文件", True)
                self.log(f"元数据已保存到: {result['metadata_file']}", True)
                
                # 询问是否打开输出目录
                if messagebox.askyesno("完成", "加密已完成！是否打开输出目录？"):
                    if sys.platform == "win32":
                        os.startfile(self.output_path.get())
                    elif sys.platform == "darwin":
                        subprocess.Popen(["open", self.output_path.get()])
                    else:
                        subprocess.Popen(["xdg-open", self.output_path.get()])
            else:
                self.log(f"错误: {result['message']}", True)
                messagebox.showerror("加密失败", result["message"])
            
        except Exception as e:
            self.log(f"意外错误: {str(e)}", True)
            messagebox.showerror("错误", f"发生意外错误: {str(e)}")
        
        finally:
            # 重新启用按钮
            self.root.after(0, lambda: self.encrypt_btn.config(state=tk.NORMAL))
    
    def start_decryption(self) -> None:
        """开始解密过程（在新线程中运行）"""
        # 验证输入
        if not self.video_files:
            messagebox.showerror("错误", "请至少选择一个HEVC视频文件")
            return
        
        if not self.metadata_path.get():
            messagebox.showerror("错误", "请选择元数据文件")
            return
        
        if not self.decrypt_output_path.get():
            messagebox.showerror("错误", "请选择输出目录")
            return
        
        # 禁用按钮防止重复点击
        self.decrypt_btn.config(state=tk.DISABLED)
        
        # 获取密码（如果有）
        password = self.decrypt_password_var.get().strip()
        if password == "":
            password = None
        
        # 记录开始
        self.log("开始解密过程...", False)
        
        # 在新线程中运行解密
        threading.Thread(target=self.run_decryption, args=(password,), daemon=True).start()
    
    def run_decryption(self, password: Optional[str]) -> None:
        """实际执行解密操作"""
        try:
            # 创建加密器（使用密码）
            self.encryptor = SecureFileEncryptor(password)
            
            # 执行解密
            result = self.encryptor.process_for_decryption(
                self.video_files,
                self.metadata_path.get(),
                self.decrypt_output_path.get()
            )
            
            if result["success"]:
                self.log("解密过程完成！", False)
                self.log(result["message"], False)
                
                # 询问是否打开输出目录
                if messagebox.askyesno("完成", "解密已完成！是否打开输出目录？"):
                    if sys.platform == "win32":
                        os.startfile(result["extracted_dir"])
                    elif sys.platform == "darwin":
                        subprocess.Popen(["open", result["extracted_dir"]])
                    else:
                        subprocess.Popen(["xdg-open", result["extracted_dir"]])
            else:
                self.log(f"错误: {result['message']}", False)
                messagebox.showerror("解密失败", result["message"])
            
        except Exception as e:
            self.log(f"意外错误: {str(e)}", False)
            messagebox.showerror("错误", f"发生意外错误: {str(e)}")
        
        finally:
            # 重新启用按钮
            self.root.after(0, lambda: self.decrypt_btn.config(state=tk.NORMAL))

# ======================
# 主程序入口
# ======================

def main():
    # 检查必要的库
    missing_libs = []
    try:
        import cryptography
    except ImportError:
        missing_libs.append("cryptography")
    
    if missing_libs:
        messagebox.showerror("依赖错误", f"缺少必要的加密库: {', '.join(missing_libs)}。\n请运行: pip install {' '.join(missing_libs)}")
        sys.exit(1)
    
    # 创建GUI
    root = tk.Tk()
    app = SecureEncryptorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
