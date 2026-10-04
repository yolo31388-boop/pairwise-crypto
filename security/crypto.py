"""
游戏内加密算法与密码学系统 - 核心模块

纯标准库实现：
- 对称加密：HMAC-SHA256 计数器模式密钥流 + Encrypt-then-MAC 完整性校验
- 非对称加密：RSA（Miller-Rabin 素数生成，PKCS#1 v1.5 风格填充）
- 哈希：SHA-256 + 随机盐
- 数字签名：RSA 签名（EMSA-PKCS1-v1_5 风格编码）
- 密钥管理：运行时生成密钥，支持轮换，不硬编码
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import hashlib
import hmac
import math
import secrets
import time


_NONCE_SIZE = 16
_TAG_SIZE = 32
_KEY_SIZE = 32
_RSA_BITS = 1024
_RSA_EXPONENT = 65537


def _to_bytes(data) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    raise TypeError("data must be bytes or str")


def _is_probable_prime(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(
            key, nonce + counter.to_bytes(8, "big"), hashlib.sha256
        ).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


@dataclass
class Config:
    pass


class Crypto:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._state = {}
        self._history = []
        self._keys: Dict[str, bytes] = {}
        self._retired_keys: Dict[str, List[bytes]] = {}
        self._keypair: Optional[Tuple[Dict, Dict]] = None

    def update(self, dt: float):
        pass

    def reset(self):
        self._state = {}
        self._history = []
        self._keys = {}
        self._retired_keys = {}
        self._keypair = None

    # ------------------------------------------------------------------
    # 密钥管理
    # ------------------------------------------------------------------
    def generate_key(self, key_id: str = "default") -> bytes:
        """生成新的随机对称密钥并登记到密钥库。"""
        key = secrets.token_bytes(_KEY_SIZE)
        if key_id in self._keys:
            self._retired_keys.setdefault(key_id, []).append(self._keys[key_id])
        self._keys[key_id] = key
        self._history.append(("generate_key", key_id, time.time()))
        return key

    def get_key(self, key_id: str = "default") -> bytes:
        """获取密钥；不存在则自动生成（密钥绝不硬编码）。"""
        if key_id not in self._keys:
            return self.generate_key(key_id)
        return self._keys[key_id]

    def rotate_key(self, key_id: str = "default") -> bytes:
        """轮换密钥：旧密钥退役存档，返回新密钥。"""
        return self.generate_key(key_id)

    # ------------------------------------------------------------------
    # 对称加密（密钥流 + Encrypt-then-MAC）
    # ------------------------------------------------------------------
    def symmetric_encrypt(self, data, key: Optional[bytes] = None,
                          key_id: str = "default") -> bytes:
        key = key if key is not None else self.get_key(key_id)
        plaintext = _to_bytes(data)
        nonce = secrets.token_bytes(_NONCE_SIZE)
        stream = _keystream(key, nonce, len(plaintext))
        ciphertext = bytes(p ^ s for p, s in zip(plaintext, stream))
        tag = hmac.new(key, b"tag" + nonce + ciphertext, hashlib.sha256).digest()
        return nonce + ciphertext + tag

    def symmetric_decrypt(self, token: bytes, key: Optional[bytes] = None,
                          key_id: str = "default") -> bytes:
        key = key if key is not None else self.get_key(key_id)
        if len(token) < _NONCE_SIZE + _TAG_SIZE:
            raise ValueError("ciphertext too short")
        nonce = token[:_NONCE_SIZE]
        tag = token[-_TAG_SIZE:]
        ciphertext = token[_NONCE_SIZE:-_TAG_SIZE]
        expected = hmac.new(key, b"tag" + nonce + ciphertext,
                            hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("integrity check failed: wrong key or tampered data")
        stream = _keystream(key, nonce, len(ciphertext))
        return bytes(c ^ s for c, s in zip(ciphertext, stream))

    # ------------------------------------------------------------------
    # 非对称加密（RSA）
    # ------------------------------------------------------------------
    def generate_keypair(self, bits: int = _RSA_BITS) -> Tuple[Dict, Dict]:
        """生成 RSA 密钥对，返回 (private_key, public_key)。"""
        half = bits // 2
        while True:
            p = _generate_prime(half)
            q = _generate_prime(half)
            if p == q:
                continue
            n = p * q
            phi = (p - 1) * (q - 1)
            if math.gcd(_RSA_EXPONENT, phi) != 1:
                continue
            d = pow(_RSA_EXPONENT, -1, phi)
            private_key = {"n": n, "d": d, "bits": bits}
            public_key = {"n": n, "e": _RSA_EXPONENT, "bits": bits}
            self._keypair = (private_key, public_key)
            self._history.append(("generate_keypair", bits, time.time()))
            return private_key, public_key

    def get_keypair(self) -> Tuple[Dict, Dict]:
        if self._keypair is None:
            return self.generate_keypair()
        return self._keypair

    def asymmetric_encrypt(self, public_key: Dict, data) -> bytes:
        n, e = public_key["n"], public_key["e"]
        k = (n.bit_length() + 7) // 8
        message = _to_bytes(data)
        if len(message) > k - 11:
            raise ValueError("message too long for key size")
        ps_len = k - len(message) - 3
        ps = bytearray()
        while len(ps) < ps_len:
            ps.extend(b for b in secrets.token_bytes(ps_len - len(ps)) if b != 0)
        em = b"\x00\x02" + bytes(ps[:ps_len]) + b"\x00" + message
        c = pow(int.from_bytes(em, "big"), e, n)
        return c.to_bytes(k, "big")

    def asymmetric_decrypt(self, private_key: Dict, token: bytes) -> bytes:
        n, d = private_key["n"], private_key["d"]
        k = (n.bit_length() + 7) // 8
        if len(token) != k:
            raise ValueError("invalid ciphertext length")
        em = pow(int.from_bytes(token, "big"), d, n).to_bytes(k, "big")
        if not em.startswith(b"\x00\x02"):
            raise ValueError("decryption failed: invalid padding")
        sep = em.find(b"\x00", 2)
        if sep < 10:
            raise ValueError("decryption failed: invalid padding")
        return em[sep + 1:]

    # ------------------------------------------------------------------
    # 哈希（SHA-256 + 随机盐）
    # ------------------------------------------------------------------
    def hash_data(self, data, salt: Optional[bytes] = None) -> Tuple[str, str]:
        """返回 (hex_hash, hex_salt)。盐随机生成，绝不使用 MD5。"""
        if salt is None:
            salt = secrets.token_bytes(16)
        digest = hashlib.sha256(salt + _to_bytes(data)).hexdigest()
        return digest, salt.hex()

    def verify_hash(self, data, hex_hash: str, hex_salt: str) -> bool:
        salt = bytes.fromhex(hex_salt)
        expected = hashlib.sha256(salt + _to_bytes(data)).hexdigest()
        return hmac.compare_digest(expected, hex_hash)

    # ------------------------------------------------------------------
    # 数字签名（RSA）
    # ------------------------------------------------------------------
    def _encode_signature_block(self, digest: bytes, k: int) -> bytes:
        return b"\x00\x01" + b"\xff" * (k - len(digest) - 3) + b"\x00" + digest

    def sign(self, private_key: Dict, data) -> bytes:
        n, d = private_key["n"], private_key["d"]
        k = (n.bit_length() + 7) // 8
        digest = hashlib.sha256(_to_bytes(data)).digest()
        em = self._encode_signature_block(digest, k)
        s = pow(int.from_bytes(em, "big"), d, n)
        return s.to_bytes(k, "big")

    def verify_signature(self, public_key: Dict, data, signature: bytes) -> bool:
        n, e = public_key["n"], public_key["e"]
        k = (n.bit_length() + 7) // 8
        if len(signature) != k:
            return False
        digest = hashlib.sha256(_to_bytes(data)).digest()
        expected = self._encode_signature_block(digest, k)
        actual = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
        return hmac.compare_digest(expected, actual)
