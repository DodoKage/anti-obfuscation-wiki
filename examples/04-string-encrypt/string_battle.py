#!/usr/bin/env python3
"""
字符串加密对抗: 加密器 vs 解密器
模拟 OLLVM Hikari 的字符串加密 + 多种解密策略
"""

import random
import struct
import base64
import hashlib


# ============================================================
#  攻击方: 字符串加密器
# ============================================================

class StringEncryptor:
    """模拟 OLLVM/Hikari 字符串加密"""

    def __init__(self):
        self.encrypted_strings = []

    def xor_single(self, plaintext, key=None):
        """方法 1: 单字节 XOR (最基础)"""
        key = key or random.randint(1, 255)
        encrypted = bytes(b ^ key for b in plaintext.encode())
        return encrypted, {'method': 'xor_single', 'key': key}

    def xor_rolling(self, plaintext, seed=None):
        """方法 2: 滚动 key XOR (模拟 Hikari)"""
        seed = seed or random.randint(1, 0xFFFFFFFF)
        key = seed
        encrypted = bytearray()
        for b in plaintext.encode():
            encrypted.append(b ^ (key & 0xFF))
            key = ((key * 1103515245 + 12345) & 0xFFFFFFFF)
        return bytes(encrypted), {'method': 'xor_rolling', 'seed': seed}

    def xor_multi_key(self, plaintext, key=None):
        """方法 3: 多字节 key XOR"""
        key = key or bytes(random.randint(1, 255) for _ in range(random.randint(4, 16)))
        encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(plaintext.encode()))
        return encrypted, {'method': 'xor_multi', 'key': list(key)}

    def add_sub(self, plaintext, key=None):
        """方法 4: ADD 加密"""
        key = key or random.randint(1, 127)
        encrypted = bytes((b + key) & 0xFF for b in plaintext.encode())
        return encrypted, {'method': 'add_sub', 'key': key}

    def rc4(self, plaintext, key=None):
        """方法 5: RC4 流加密"""
        key = key or bytes(random.randint(0, 255) for _ in range(16))

        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]

        encrypted = bytearray()
        i = j = 0
        for b in plaintext.encode():
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            encrypted.append(b ^ k)

        return bytes(encrypted), {'method': 'rc4', 'key': list(key)}

    def stack_string(self, plaintext):
        """方法 6: 栈字符串 (逐字符异或赋值)"""
        key = random.randint(1, 255)
        assignments = []
        for i, ch in enumerate(plaintext):
            encrypted_byte = ord(ch) ^ key
            assignments.append(f"buf[{i}] = {encrypted_byte:#04x} ^ {key:#04x}")
        assignments.append(f"buf[{len(plaintext)}] = 0x00")
        return assignments, {'method': 'stack_string', 'key': key, 'length': len(plaintext)}

    def encrypt_all(self, strings):
        """对字符串列表应用随机加密方法"""
        methods = [self.xor_single, self.xor_rolling, self.xor_multi_key, self.add_sub, self.rc4]
        results = []

        for s in strings:
            method = random.choice(methods)
            encrypted, info = method(s)
            info['original_length'] = len(s)
            results.append({
                'plaintext': s,
                'encrypted': encrypted,
                'info': info,
            })
            self.encrypted_strings.append(results[-1])

        return results


# ============================================================
#  防御方: 字符串解密器
# ============================================================

class StringDecryptor:
    """通用字符串解密器"""

    @staticmethod
    def try_xor_single(data):
        """尝试所有单字节 XOR key"""
        results = []
        for key in range(1, 256):
            decrypted = bytes(b ^ key for b in data)
            if StringDecryptor._is_printable(decrypted):
                results.append((key, decrypted.decode('ascii', errors='replace')))
        return results

    @staticmethod
    def try_xor_rolling(data, max_seeds=100000):
        """暴力搜索 rolling XOR seed"""
        for seed in range(1, max_seeds):
            key = seed
            decrypted = bytearray()
            for b in data:
                decrypted.append(b ^ (key & 0xFF))
                key = ((key * 1103515245 + 12345) & 0xFFFFFFFF)
            if StringDecryptor._is_printable(bytes(decrypted)):
                return seed, bytes(decrypted).decode('ascii', errors='replace')
        return None

    @staticmethod
    def try_add_sub(data):
        """尝试所有 ADD/SUB key"""
        results = []
        for key in range(1, 256):
            decrypted = bytes((b - key) & 0xFF for b in data)
            if StringDecryptor._is_printable(decrypted):
                results.append((key, decrypted.decode('ascii', errors='replace')))
        return results

    @staticmethod
    def try_rc4(data, key):
        """已知 key 的 RC4 解密"""
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]

        decrypted = bytearray()
        i = j = 0
        for b in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            decrypted.append(b ^ k)

        return bytes(decrypted)

    @staticmethod
    def frequency_analysis(data):
        """频率分析: 假设最常见字节对应空格 (0x20)"""
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1

        if not freq:
            return []

        most_common = max(freq, key=freq.get)
        possible_key = most_common ^ 0x20  # 假设对应空格
        decrypted = bytes(b ^ possible_key for b in data)
        if StringDecryptor._is_printable(decrypted):
            return [(possible_key, decrypted.decode('ascii', errors='replace'))]
        return []

    @staticmethod
    def known_plaintext_attack(data, known_prefix):
        """已知明文攻击: 从已知前缀推导 key"""
        if len(known_prefix) == 0:
            return []

        # XOR 已知明文与密文得到 key stream
        key_stream = bytes(data[i] ^ ord(known_prefix[i])
                          for i in range(min(len(data), len(known_prefix))))

        # 检查 key 是否为单字节重复
        if len(set(key_stream)) == 1:
            key = key_stream[0]
            decrypted = bytes(b ^ key for b in data)
            return [('xor_single', key, decrypted.decode('ascii', errors='replace'))]

        # 检查 key 是否为多字节重复
        for key_len in range(2, min(17, len(key_stream) + 1)):
            key = key_stream[:key_len]
            decrypted = bytes(data[i] ^ key[i % key_len] for i in range(len(data)))
            if StringDecryptor._is_printable(decrypted):
                return [('xor_multi', list(key), decrypted.decode('ascii', errors='replace'))]

        return []

    @staticmethod
    def _is_printable(data):
        """检查数据是否为可打印 ASCII"""
        return all(0x20 <= b < 0x7F or b == 0x0A or b == 0x0D for b in data)

    @staticmethod
    def auto_decrypt(data, hints=None):
        """自动尝试所有解密方法"""
        results = []

        # 1. 单字节 XOR
        xor_results = StringDecryptor.try_xor_single(data)
        for key, text in xor_results:
            results.append(('xor_single', f'key=0x{key:02X}', text))

        # 2. ADD/SUB
        add_results = StringDecryptor.try_add_sub(data)
        for key, text in add_results:
            results.append(('add_sub', f'key={key}', text))

        # 3. 频率分析
        freq_results = StringDecryptor.frequency_analysis(data)
        for key, text in freq_results:
            results.append(('freq_analysis', f'key=0x{key:02X}', text))

        return results


# ============================================================
#  对抗演示
# ============================================================

def battle():
    print("=" * 70)
    print("  字符串加密对抗: 加密器 vs 解密器")
    print("=" * 70)

    encryptor = StringEncryptor()

    test_strings = [
        "password123",
        "https://api.evil.com/c2",
        "SELECT * FROM users WHERE id=1",
        "AES-256-CBC",
        "/etc/shadow",
    ]

    for plaintext in test_strings:
        print(f"\n{'─'*70}")
        print(f"[明文] \"{plaintext}\"")
        print(f"{'─'*70}")

        # 攻击方: 加密
        encrypted, info = encryptor.xor_single(plaintext)
        method = info['method']
        print(f"  [攻击方] 方法: {method}")
        print(f"           密文: {encrypted.hex()}")

        # 防御方: 解密
        results = StringDecryptor.auto_decrypt(encrypted)
        cracked = False
        for method_name, key_info, decrypted in results:
            if decrypted == plaintext:
                print(f"  [防御方] {method_name} ({key_info}) → \"{decrypted}\" [CRACKED]")
                cracked = True
                break

        if not cracked:
            print(f"  [防御方] 自动解密失败")

    # 高强度: rolling XOR
    print(f"\n{'='*70}")
    print("  高强度对抗: Rolling XOR")
    print(f"{'='*70}")

    plaintext = "secret_api_key_12345"
    encrypted, info = encryptor.xor_rolling(plaintext, seed=42)
    print(f"\n  [攻击方] Rolling XOR (seed=42)")
    print(f"           明文: \"{plaintext}\"")
    print(f"           密文: {encrypted.hex()}")

    result = StringDecryptor.try_xor_rolling(encrypted, max_seeds=100)
    if result:
        seed, decrypted = result
        print(f"  [防御方] 暴力搜索 seed={seed} → \"{decrypted}\" [CRACKED]")
    else:
        print(f"  [防御方] 暴力搜索失败 (seed 超出搜索范围)")

    # 已知明文攻击
    print(f"\n{'='*70}")
    print("  已知明文攻击")
    print(f"{'='*70}")

    plaintext = "Content-Type: application/json"
    encrypted, info = encryptor.xor_single(plaintext)
    print(f"\n  [攻击方] 单字节 XOR 加密 HTTP header")
    print(f"           密文: {encrypted.hex()[:40]}...")

    results = StringDecryptor.known_plaintext_attack(encrypted, "Content-")
    for method_name, key, decrypted in results:
        matched = decrypted == plaintext
        print(f"  [防御方] 已知 \"Content-\" → {method_name} key=0x{key:02X}")
        print(f"           还原: \"{decrypted}\" [{'CRACKED' if matched else 'PARTIAL'}]")


if __name__ == '__main__':
    battle()
