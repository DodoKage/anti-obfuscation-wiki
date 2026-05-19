# 字符串加密 (String Encryption) 分析

## 实现原理

### OLLVM/Hikari 字符串加密

```
编译时:
1. 扫描所有全局字符串常量
2. 用随机密钥对每个字符串进行 XOR 加密
3. 将加密后的字符串存入 .data / .rodata section
4. 生成解密函数，在 __attribute__((constructor)) 或首次使用时调用
5. 解密函数在运行时还原明文

内存布局:
┌─────────────────────────────────────┐
│ .rodata (编译后)                     │
│ encrypted_str_1: DB 0xA3,0xB4,...   │
│ encrypted_str_2: DB 0xC5,0xD6,...   │
│ ...                                 │
└─────────────────────────────────────┘
         ↓ (运行时 constructor 解密)
┌─────────────────────────────────────┐
│ .data (运行时)                       │
│ decrypted_str_1: "password"         │
│ decrypted_str_2: "secret_key"       │
│ ...                                 │
└─────────────────────────────────────┘
```

### 解密函数模式

```c
// 典型的 Hikari 字符串解密函数
__attribute__((constructor))
void decrypt_strings() {
    // 解密 string_1
    char* str1 = (char*)encrypted_string_1;
    for (int i = 0; i < str1_len; i++) {
        str1[i] ^= key1[i % key1_len];
    }
    
    // 解密 string_2
    char* str2 = (char*)encrypted_string_2;
    for (int i = 0; i < str2_len; i++) {
        str2[i] ^= key2;  // 简单单字节 key
    }
    
    // ... 更多字符串
}
```

### 汇编层面

```asm
; 典型解密循环 (x86)
decrypt_string_1:
    lea     esi, [encrypted_data]
    mov     ecx, STRING_LENGTH
    mov     al, XOR_KEY
    
.decrypt_loop:
    xor     byte ptr [esi], al
    inc     esi
    dec     ecx
    jnz     .decrypt_loop
    ret

; ARM 版本
decrypt_string_1:
    LDR     R0, =encrypted_data
    MOV     R1, #STRING_LENGTH
    MOV     R2, #XOR_KEY
    
.loop:
    LDRB    R3, [R0]
    EOR     R3, R3, R2
    STRB    R3, [R0], #1
    SUBS    R1, R1, #1
    BNE     .loop
    BX      LR
```

## 加密变体

### 变体 1: 多字节 Key XOR

```c
void decrypt(char* data, int len, const char* key, int key_len) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}
```

### 变体 2: 滚动 Key

```c
void decrypt_rolling(char* data, int len, uint32_t seed) {
    uint32_t key = seed;
    for (int i = 0; i < len; i++) {
        data[i] ^= (key & 0xFF);
        key = key * 1103515245 + 12345;  // LCG
    }
}
```

### 变体 3: AES/RC4 加密

```c
void decrypt_aes(char* data, int len, const uint8_t* aes_key) {
    AES_KEY dec_key;
    AES_set_decrypt_key(aes_key, 128, &dec_key);
    
    for (int i = 0; i < len; i += 16) {
        AES_ecb_encrypt(data + i, data + i, &dec_key, AES_DECRYPT);
    }
}
```

### 变体 4: 编码 + 加密

```c
void decrypt_base64_xor(const char* encoded, char* output) {
    // Step 1: Base64 解码
    int decoded_len = base64_decode(encoded, output);
    
    // Step 2: XOR 解密
    for (int i = 0; i < decoded_len; i++) {
        output[i] ^= KEY;
    }
}
```

### 变体 5: 堆栈字符串 (Stack Strings)

```c
// 不存储在全局区，而是在运行时在栈上构造
void use_hidden_string() {
    char str[16];
    str[0] = 'p' ^ 0x42;  // 每个字符单独赋值
    str[1] = 'a' ^ 0x42;
    str[2] = 's' ^ 0x42;
    str[3] = 's' ^ 0x42;
    str[4] = 'w' ^ 0x42;
    str[5] = 'o' ^ 0x42;
    str[6] = 'r' ^ 0x42;
    str[7] = 'd' ^ 0x42;
    str[8] = 0;
    
    // 解密
    for (int i = 0; i < 8; i++) str[i] ^= 0x42;
    
    // 使用
    check_password(str);
    
    // 清除
    memset(str, 0, sizeof(str));
}
```

## 字符串解密方法

### 方法 1: 动态提取 (最简单)

```python
# 方法: 让程序自己解密，然后从内存中提取
import frida

def dump_decrypted_strings(process_name):
    session = frida.attach(process_name)
    
    script = session.create_script("""
    // 等待 constructor 执行完毕后扫描内存
    setTimeout(function() {
        var results = [];
        
        // 扫描可读内存区域中的 ASCII 字符串
        Process.enumerateRanges('r--').forEach(function(range) {
            try {
                var data = Memory.readByteArray(range.base, 
                           Math.min(range.size, 0x100000));
                var bytes = new Uint8Array(data);
                
                var current = '';
                for (var i = 0; i < bytes.length; i++) {
                    if (bytes[i] >= 0x20 && bytes[i] < 0x7F) {
                        current += String.fromCharCode(bytes[i]);
                    } else {
                        if (current.length >= 4) {
                            results.push({
                                addr: range.base.add(i - current.length).toString(),
                                str: current
                            });
                        }
                        current = '';
                    }
                }
            } catch(e) {}
        });
        
        send({type: 'strings', data: results});
    }, 1000);
    """)
    
    strings = []
    script.on('message', lambda msg, data: strings.extend(msg['payload']['data']))
    script.load()
    
    import time
    time.sleep(3)
    
    return strings
```

### 方法 2: Hook 解密函数

```javascript
// Frida: Hook constructor 中的解密函数
Interceptor.attach(Module.findExportByName(null, '__cxa_atexit'), {
    onEnter: function(args) {
        // constructor 通常在 __cxa_atexit 之前执行
        // 此时字符串已经解密
    }
});

// 更精确: Hook 特定的解密函数
var decryptFunc = Module.findBaseAddress('libtarget.so').add(0x1234);
Interceptor.attach(decryptFunc, {
    onEnter: function(args) {
        this.buf = args[0];
        this.len = args[1].toInt32();
        console.log('Decrypting at: ' + this.buf + ' len=' + this.len);
    },
    onLeave: function(retval) {
        console.log('Decrypted: ' + Memory.readUtf8String(this.buf, this.len));
    }
});
```

### 方法 3: 静态解密 (逆向密钥)

```python
# IDA Python: 静态提取并解密字符串

def find_xor_decrypt_loops(func_addr):
    """在函数中查找 XOR 解密循环"""
    func = idaapi.get_func(func_addr)
    
    for block in idaapi.FlowChart(func):
        insns = list(idautils.Heads(block.start_ea, block.end_ea))
        
        for addr in insns:
            mnem = idc.print_insn_mnem(addr)
            if mnem == 'xor':
                # 检查是否是对内存的 XOR
                op0_type = idc.get_operand_type(addr, 0)
                if op0_type in [idc.o_mem, idc.o_phrase, idc.o_displ]:
                    # 获取 XOR key
                    op1_type = idc.get_operand_type(addr, 1)
                    if op1_type == idc.o_imm:
                        key = idc.get_operand_value(addr, 1)
                        print(f"XOR decrypt at {addr:#x}, key=0x{key:x}")

def decrypt_string_static(encrypted_data, key, method='xor_byte'):
    """静态解密字符串"""
    if method == 'xor_byte':
        return bytes(b ^ key for b in encrypted_data)
    elif method == 'xor_multi':
        key_bytes = key.to_bytes((key.bit_length() + 7) // 8, 'little')
        return bytes(b ^ key_bytes[i % len(key_bytes)] 
                    for i, b in enumerate(encrypted_data))
    elif method == 'rolling_xor':
        result = bytearray()
        k = key
        for b in encrypted_data:
            result.append(b ^ (k & 0xFF))
            k = (k * 1103515245 + 12345) & 0xFFFFFFFF
        return bytes(result)
```

### 方法 4: Emulation 解密

```python
# 使用 Unicorn 模拟执行解密函数
from unicorn import *
from unicorn.x86_const import *

def emulate_decrypt(decrypt_func_bytes, encrypted_data, func_addr=0x1000):
    """模拟执行解密函数"""
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    
    # 映射内存
    uc.mem_map(func_addr, 0x10000)       # 代码
    uc.mem_map(0x800000, 0x10000)         # 数据
    uc.mem_map(0x7FF00000, 0x10000)       # 栈
    
    # 写入代码和数据
    uc.mem_write(func_addr, decrypt_func_bytes)
    uc.mem_write(0x800000, encrypted_data)
    
    # 设置参数 (cdecl: 参数在栈上)
    uc.reg_write(UC_X86_REG_ESP, 0x7FF08000)
    # push data_addr
    uc.mem_write(0x7FF08000, b'\x00\x00\x80\x00')  # data ptr
    # push data_len
    uc.mem_write(0x7FF08004, len(encrypted_data).to_bytes(4, 'little'))
    
    # 执行
    try:
        uc.emu_start(func_addr, func_addr + len(decrypt_func_bytes))
    except UcError:
        pass
    
    # 读取解密后的数据
    decrypted = uc.mem_read(0x800000, len(encrypted_data))
    return bytes(decrypted)
```

### 方法 5: FLOSS (FireEye Labs Obfuscated String Solver)

```bash
# FLOSS: 自动化字符串解密工具
# 安装
pip install floss

# 使用
floss target.exe

# FLOSS 会自动:
# 1. 提取普通字符串
# 2. 模拟执行解密函数
# 3. 提取堆栈字符串
# 4. 输出所有解密后的字符串
```

## 批量字符串解密框架

```python
class StringDecryptor:
    """通用字符串解密框架"""
    
    def __init__(self, binary_path):
        self.binary = binary_path
        self.decrypted = {}
    
    def auto_decrypt(self):
        """自动检测并解密所有字符串"""
        # 1. 查找 constructor 函数
        constructors = self.find_constructors()
        
        # 2. 分析每个 constructor
        for ctor in constructors:
            decrypt_info = self.analyze_decrypt_function(ctor)
            if decrypt_info:
                # 3. 提取加密数据和密钥
                for info in decrypt_info:
                    encrypted = self.read_data(info['data_addr'], info['data_len'])
                    key = info['key']
                    method = info['method']
                    
                    # 4. 解密
                    decrypted = self.decrypt(encrypted, key, method)
                    self.decrypted[info['data_addr']] = decrypted.decode('utf-8', errors='ignore')
        
        return self.decrypted
    
    def find_constructors(self):
        """查找 .init_array / .ctors 中的函数"""
        import lief
        binary = lief.parse(self.binary)
        
        init_array = binary.get_section('.init_array')
        if init_array:
            data = bytes(init_array.content)
            ptrs = []
            for i in range(0, len(data), 4):
                addr = int.from_bytes(data[i:i+4], 'little')
                if addr != 0:
                    ptrs.append(addr)
            return ptrs
        
        return []
```
