"""
游戏内加密算法与密码学系统 - 核心模块

功能：
- 对称加密：HMAC-SHA256 派生密钥流的 CTR 模式加密 + Encrypt-then-MAC 认证
- 非对称加密：纯标准库 RSA（Miller-Rabin 素数生成，PKCS#1 v1.5 风格填充）
- 哈希：PBKDF2-HMAC-SHA256 加盐哈希（不再使用 MD5、不再无盐）
- 数字签名：RSA + SHA-256 签名/验签，可检测存档篡改
- 密钥管理：运行时安全生成、存储、轮换密钥，不硬编码
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import hashlib
import hmac
import math
import secrets
import time


@dataclass
class Config:
    pass


# ---------------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------------

def _to_bytes(data) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("utf-8")
    raise TypeError("data must be bytes or str")


def _int_to_bytes(value: int, length: Optional[int] = None) -> bytes:
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def _bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


# ---------------------------------------------------------------------------
# 对称加密（CTR 密钥流 + HMAC 认证）
# ---------------------------------------------------------------------------

_NONCE_SIZE = 16
_MAC_SIZE = 32


def _derive_keys(key: bytes) -> Tuple[bytes, bytes]:
    enc_key = hmac.new(key, b"enc", hashlib.sha256).digest()
    mac_key = hmac.new(key, b"mac", hashlib.sha256).digest()
    return enc_key, mac_key


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(enc_key, nonce + counter.to_bytes(8, "big"),
                        hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def symmetric_encrypt(plaintext, key: bytes) -> bytes:
    """加密并认证：nonce || ciphertext || HMAC 标签。"""
    data = _to_bytes(plaintext)
    enc_key, mac_key = _derive_keys(key)
    nonce = secrets.token_bytes(_NONCE_SIZE)
    stream = _keystream(enc_key, nonce, len(data))
    ciphertext = bytes(a ^ b for a, b in zip(data, stream))
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + ciphertext + tag


def symmetric_decrypt(token: bytes, key: bytes) -> bytes:
    """解密并校验认证标签，篡改会抛出 ValueError。"""
    token = _to_bytes(token)
    if len(token) < _NONCE_SIZE + _MAC_SIZE:
        raise ValueError("ciphertext too short")
    nonce = token[:_NONCE_SIZE]
    tag = token[-_MAC_SIZE:]
    ciphertext = token[_NONCE_SIZE:-_MAC_SIZE]
    enc_key, mac_key = _derive_keys(key)
    expected = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed: data tampered or wrong key")
    stream = _keystream(enc_key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream))


# ---------------------------------------------------------------------------
# 非对称加密（RSA）
# ---------------------------------------------------------------------------

_SMALL_PRIMES = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
    149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
    227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
    307, 311, 313, 317, 331, 337, 347, 349,
]


def _is_probable_prime(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
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


def generate_keypair(bits: int = 1024) -> Tuple[Dict[str, int], Dict[str, int]]:
    """生成 RSA 密钥对，返回 (public_key, private_key)。"""
    e = 65537
    half = bits // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(bits - half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            break
    n = p * q
    d = pow(e, -1, phi)
    return {"n": n, "e": e}, {"n": n, "d": d}


def _pkcs1_pad(message: bytes, key_bytes: int) -> bytes:
    if len(message) > key_bytes - 11:
        raise ValueError("message too long for key size")
    padding_len = key_bytes - len(message) - 3
    padding = bytearray()
    while len(padding) < padding_len:
        chunk = secrets.token_bytes(padding_len - len(padding))
        padding += bytes(b for b in chunk if b != 0)
    return b"\x00\x02" + bytes(padding[:padding_len]) + b"\x00" + message


def _pkcs1_unpad(padded: bytes) -> bytes:
    if len(padded) < 11 or not padded.startswith(b"\x00\x02"):
        raise ValueError("decryption failed: invalid padding")
    sep = padded.find(b"\x00", 2)
    if sep < 10:
        raise ValueError("decryption failed: invalid padding")
    return padded[sep + 1:]


def asymmetric_encrypt(plaintext, public_key: Dict[str, int]) -> bytes:
    """用公钥加密。"""
    data = _to_bytes(plaintext)
    n, e = public_key["n"], public_key["e"]
    key_bytes = (n.bit_length() + 7) // 8
    padded = _pkcs1_pad(data, key_bytes)
    return _int_to_bytes(pow(_bytes_to_int(padded), e, n), key_bytes)


def asymmetric_decrypt(ciphertext, private_key: Dict[str, int]) -> bytes:
    """用私钥解密。"""
    data = _to_bytes(ciphertext)
    n, d = private_key["n"], private_key["d"]
    key_bytes = (n.bit_length() + 7) // 8
    if len(data) != key_bytes:
        raise ValueError("invalid ciphertext length")
    padded = _int_to_bytes(pow(_bytes_to_int(data), d, n), key_bytes)
    return _pkcs1_unpad(padded)


# ---------------------------------------------------------------------------
# 哈希（加盐 PBKDF2-HMAC-SHA256）
# ---------------------------------------------------------------------------

_SALT_SIZE = 16
_PBKDF2_ITERATIONS = 100_000


def hash_data(data, salt: Optional[bytes] = None,
              iterations: int = _PBKDF2_ITERATIONS) -> str:
    """加盐哈希，返回 'iterations$salt_hex$hash_hex'。不再使用 MD5。"""
    raw = _to_bytes(data)
    if salt is None:
        salt = secrets.token_bytes(_SALT_SIZE)
    digest = hashlib.pbkdf2_hmac("sha256", raw, salt, iterations)
    return f"{iterations}${salt.hex()}${digest.hex()}"


def verify_hash(data, stored: str) -> bool:
    """校验数据是否与存储的加盐哈希匹配。"""
    try:
        iterations_s, salt_hex, hash_hex = stored.split("$")
        iterations = int(iterations_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", _to_bytes(data), salt, iterations)
    return hmac.compare_digest(actual, expected)


# ---------------------------------------------------------------------------
# 数字签名（RSA + SHA-256）
# ---------------------------------------------------------------------------

_SHA256_DER_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def sign(data, private_key: Dict[str, int]) -> bytes:
    """用私钥对数据签名。"""
    digest = hashlib.sha256(_to_bytes(data)).digest()
    n, d = private_key["n"], private_key["d"]
    key_bytes = (n.bit_length() + 7) // 8
    t = _SHA256_DER_PREFIX + digest
    padding = b"\xff" * (key_bytes - len(t) - 3)
    em = b"\x00\x01" + padding + b"\x00" + t
    return _int_to_bytes(pow(_bytes_to_int(em), d, n), key_bytes)


def verify(data, signature, public_key: Dict[str, int]) -> bool:
    """用公钥验签；数据被篡改或签名无效时返回 False。"""
    try:
        sig = _to_bytes(signature)
        n, e = public_key["n"], public_key["e"]
        key_bytes = (n.bit_length() + 7) // 8
        if len(sig) != key_bytes:
            return False
        em = _int_to_bytes(pow(_bytes_to_int(sig), e, n), key_bytes)
        digest = hashlib.sha256(_to_bytes(data)).digest()
        t = _SHA256_DER_PREFIX + digest
        padding = b"\xff" * (key_bytes - len(t) - 3)
        expected = b"\x00\x01" + padding + b"\x00" + t
        return hmac.compare_digest(em, expected)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


# ---------------------------------------------------------------------------
# Crypto 系统门面
# ---------------------------------------------------------------------------

class Crypto:
    """游戏内加密系统：对称/非对称加密、加盐哈希、数字签名与密钥管理。"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._state = {}
        self._history = []
        self._keys: Dict[str, bytes] = {}
        self._keypairs: Dict[str, Tuple[Dict, Dict]] = {}

    def update(self, dt: float):
        pass

    def reset(self):
        self._state = {}
        self._history = []
        self._keys = {}
        self._keypairs = {}

    # ---- 对称加密 ----

    def generate_key(self, length: int = 32) -> bytes:
        """用安全随机源生成对称密钥（不硬编码）。"""
        return secrets.token_bytes(length)

    def symmetric_encrypt(self, plaintext, key: Optional[bytes] = None) -> bytes:
        key = key if key is not None else self._default_symmetric_key()
        return symmetric_encrypt(plaintext, key)

    def symmetric_decrypt(self, token, key: Optional[bytes] = None) -> bytes:
        key = key if key is not None else self._default_symmetric_key()
        return symmetric_decrypt(token, key)

    # 兼容别名
    encrypt = symmetric_encrypt
    decrypt = symmetric_decrypt

    def _default_symmetric_key(self) -> bytes:
        if "default" not in self._keys:
            self._keys["default"] = self.generate_key()
        return self._keys["default"]

    # ---- 非对称加密 ----

    def generate_keypair(self, bits: int = 1024,
                         key_id: Optional[str] = None) -> Tuple[Dict, Dict]:
        public_key, private_key = generate_keypair(bits)
        if key_id is not None:
            self._keypairs[key_id] = (public_key, private_key)
        return public_key, private_key

    def asymmetric_encrypt(self, plaintext, public_key: Dict) -> bytes:
        return asymmetric_encrypt(plaintext, public_key)

    def asymmetric_decrypt(self, ciphertext, private_key: Dict) -> bytes:
        return asymmetric_decrypt(ciphertext, private_key)

    public_encrypt = asymmetric_encrypt
    private_decrypt = asymmetric_decrypt

    # ---- 哈希 ----

    def hash(self, data, salt: Optional[bytes] = None) -> str:
        return hash_data(data, salt)

    def hash_password(self, password, salt: Optional[bytes] = None) -> str:
        return hash_data(password, salt)

    def verify_hash(self, data, stored: str) -> bool:
        return verify_hash(data, stored)

    def verify_password(self, password, stored: str) -> bool:
        return verify_hash(password, stored)

    # ---- 数字签名 ----

    def sign(self, data, private_key: Dict) -> bytes:
        return sign(data, private_key)

    def verify(self, data, signature, public_key: Dict) -> bool:
        return verify(data, signature, public_key)

    # ---- 密钥管理 ----

    def create_key(self, key_id: str, length: int = 32) -> bytes:
        """生成并登记一个新密钥。"""
        key = self.generate_key(length)
        self._keys[key_id] = key
        self._history.append(("create", key_id, time.time()))
        return key

    def get_key(self, key_id: str) -> bytes:
        if key_id not in self._keys:
            raise KeyError(f"unknown key id: {key_id}")
        return self._keys[key_id]

    def rotate_key(self, key_id: str, length: int = 32) -> bytes:
        """轮换密钥：生成新密钥替换旧密钥。"""
        key = self.generate_key(length)
        self._keys[key_id] = key
        self._history.append(("rotate", key_id, time.time()))
        return key

    def delete_key(self, key_id: str) -> None:
        self._keys.pop(key_id, None)
        self._history.append(("delete", key_id, time.time()))

    def list_keys(self) -> List[str]:
        return list(self._keys.keys())
