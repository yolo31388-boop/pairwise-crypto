"""
游戏内加密算法与密码学系统 - 验收测试
运行方式：python -m pytest tests/test_crypto.py -q
共 16 个测试用例
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.crypto import Crypto


class TestCrypto:
    def setup_method(self):
        self.system = Crypto()

    # ---- 对称加密 ----
    def test_case_01(self):
        # 对称加密不能是明文：密文必须与原文不同
        token = self.system.symmetric_encrypt("player_save_data")
        assert b"player_save_data" not in token
        assert token != b"player_save_data"

    def test_case_02(self):
        # 加密后可正确解密还原
        message = b"level=12;gold=9999;hp=100"
        token = self.system.symmetric_encrypt(message)
        assert self.system.symmetric_decrypt(token) == message

    def test_case_03(self):
        # 错误密钥无法解密
        token = self.system.symmetric_encrypt(b"secret", key=self.system.generate_key("a"))
        wrong_key = self.system.generate_key("b")
        with pytest.raises(ValueError):
            self.system.symmetric_decrypt(token, key=wrong_key)

    def test_case_04(self):
        # 篡改密文能被完整性校验发现
        token = bytearray(self.system.symmetric_encrypt(b"important save"))
        token[len(token) // 2] ^= 0x01
        with pytest.raises(ValueError):
            self.system.symmetric_decrypt(bytes(token))

    # ---- 非对称加密 ----
    def test_case_05(self):
        # 能生成 RSA 密钥对，模数长度达标
        private_key, public_key = self.system.generate_keypair()
        assert private_key["n"] == public_key["n"]
        assert public_key["e"] == 65537
        assert public_key["n"].bit_length() >= 1023

    def test_case_06(self):
        # 公钥加密、私钥解密往返
        private_key, public_key = self.system.generate_keypair()
        message = b"trade: sword x1 for 300 gold"
        token = self.system.asymmetric_encrypt(public_key, message)
        assert token != message
        assert self.system.asymmetric_decrypt(private_key, token) == message

    def test_case_07(self):
        # 密钥随机生成而非硬编码：两次生成的密钥对不同
        _, public_key1 = self.system.generate_keypair()
        other = Crypto()
        _, public_key2 = other.generate_keypair()
        assert public_key1["n"] != public_key2["n"]

    def test_case_08(self):
        # 私钥不匹配时无法解密
        _, public_key = self.system.generate_keypair()
        other_private, _ = Crypto().generate_keypair()
        token = self.system.asymmetric_encrypt(public_key, b"loot drop table")
        try:
            result = self.system.asymmetric_decrypt(other_private, token)
            assert result != b"loot drop table"
        except ValueError:
            pass

    # ---- 哈希 ----
    def test_case_09(self):
        # 使用 SHA-256（64位十六进制），而不是 MD5（32位）
        hex_hash, _ = self.system.hash_data("password123")
        assert len(hex_hash) == 64
        assert hex_hash != "e99a18c428cb38d5f260853678922e03"  # MD5("abc123") 风格

    def test_case_10(self):
        # 加盐：同一数据两次哈希结果不同，盐也不同
        hash1, salt1 = self.system.hash_data("password123")
        hash2, salt2 = self.system.hash_data("password123")
        assert salt1 != salt2
        assert hash1 != hash2

    def test_case_11(self):
        # 哈希校验：正确数据通过，错误数据失败
        hex_hash, salt = self.system.hash_data("password123")
        assert self.system.verify_hash("password123", hex_hash, salt)
        assert not self.system.verify_hash("password124", hex_hash, salt)

    # ---- 数字签名 ----
    def test_case_12(self):
        # 私钥签名、公钥验签通过
        private_key, public_key = self.system.get_keypair()
        save_data = b"save_slot_1: level=12;gold=9999"
        signature = self.system.sign(private_key, save_data)
        assert self.system.verify_signature(public_key, save_data, signature)

    def test_case_13(self):
        # 存档被篡改后验签失败
        private_key, public_key = self.system.get_keypair()
        save_data = b"save_slot_1: gold=100"
        signature = self.system.sign(private_key, save_data)
        tampered = b"save_slot_1: gold=999999"
        assert not self.system.verify_signature(public_key, tampered, signature)

    # ---- 密钥管理 ----
    def test_case_14(self):
        # 密钥不硬编码：不同实例的默认密钥不同
        other = Crypto()
        assert self.system.get_key() != other.get_key()

    def test_case_15(self):
        # 密钥轮换后新旧密钥不同，且旧密钥无法解密新数据
        old_key = self.system.get_key()
        new_key = self.system.rotate_key()
        assert old_key != new_key
        token = self.system.symmetric_encrypt(b"fresh data")
        with pytest.raises(ValueError):
            self.system.symmetric_decrypt(token, key=old_key)

    def test_case_16(self):
        # reset 清空密钥与状态，之后重新生成全新密钥
        old_key = self.system.get_key()
        self.system.symmetric_encrypt(b"something")
        self.system.reset()
        assert self.system._state == {}
        assert self.system._history == []
        assert self.system.get_key() != old_key


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
