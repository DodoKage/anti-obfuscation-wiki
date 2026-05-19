# VMP 虚拟机架构深度分析

## VM 执行模型

### 整体架构

```
┌──────────────────────────────────────────────────────────┐
│                     VMP Virtual Machine                   │
│                                                          │
│  ┌─────────┐    ┌─────────────┐    ┌──────────────────┐ │
│  │ VMEntry  │───→│ VMDispatcher│───→│   VMHandlers     │ │
│  │          │    │  (主循环)    │    │  ┌────────────┐  │ │
│  │ 保存上下文│    │  fetch      │    │  │ vAdd       │  │ │
│  │ 初始化VM │    │  decode     │    │  │ vSub       │  │ │
│  │ 跳转分发  │    │  dispatch   │    │  │ vMov       │  │ │
│  └─────────┘    └──────┬──────┘    │  │ vPush/vPop │  │ │
│                        │           │  │ vNand      │  │ │
│  ┌─────────┐           │           │  │ vCmp       │  │ │
│  │ VMExit  │←──────────┘           │  │ vJmp/vJcc  │  │ │
│  │          │    (遇到exit指令)     │  │ vCall      │  │ │
│  │ 恢复上下文│                      │  │ vRet       │  │ │
│  │ 返回原始  │                      │  │ ...        │  │ │
│  └─────────┘                       │  └────────────┘  │ │
│                                    └──────────────────┘ │
│  ┌────────────────────────────────────────────────────┐ │
│  │                  VMContext                          │ │
│  │  虚拟寄存器组 | 虚拟栈 | 虚拟标志位 | 字节码指针    │ │
│  └────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

## VMEntry 详解

VMEntry 是 VM 的入口点，负责从原始执行环境切换到虚拟执行环境。

### VMP 2.x VMEntry 典型模式

```asm
; 1. 压入加密的 bytecode 地址
push    encrypted_bytecode_addr

; 2. 保存通用寄存器 (pushad 或逐个 push)
pushad                          ; 保存 EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI
pushfd                          ; 保存 EFLAGS

; 3. 初始化 VM 上下文
mov     esi, [esp+24h]          ; ESI = bytecode 指针 (VIP - Virtual Instruction Pointer)
mov     ebp, esp                ; EBP = 虚拟栈指针 (VSP - Virtual Stack Pointer)
sub     esp, VM_CONTEXT_SIZE    ; 分配虚拟寄存器空间
mov     edi, esp                ; EDI = 虚拟寄存器基址

; 4. 解密 bytecode 地址
xor     esi, KEY1
add     esi, KEY2
rol     esi, KEY3

; 5. 跳转到 dispatcher
jmp     vm_dispatcher
```

### VMP 3.x VMEntry 特征

VMP 3.x 的 VMEntry 更加混淆：
- pushad/pushfd 被拆分为单独的 push 指令序列
- 大量垃圾指令插入
- 寄存器别名随机化
- 密钥运算更复杂（多级 XOR/ROL/ROR/ADD/SUB）
- 可能使用不同的寄存器约定

## VMDispatcher 详解

Dispatcher 是 VM 的核心循环，实现取指-解码-分发。

### 经典 Dispatcher 模式

```asm
vm_dispatcher:
    ; 1. 取指 (Fetch): 读取一字节 opcode
    movzx   eax, byte ptr [esi]     ; 读取 bytecode
    
    ; 2. 更新 VIP
    add     esi, 1                   ; VIP += 1 (或 sub，取决于方向)
    
    ; 3. 解码 (Decode): 解密 opcode
    xor     al, KEY                  ; 解密
    
    ; 4. 分发 (Dispatch): 跳转到对应 handler
    jmp     dword ptr [handler_table + eax*4]   ; 跳转表分发
```

### VMP 3.x Dispatcher 变体

#### 变体 1: 计算跳转 (Computed Jump)
```asm
movzx   eax, byte ptr [esi]
lea     esi, [esi+1]              ; VIP++
xor     al, bl                    ; 使用动态 key 解密
movzx   eax, al
; 不使用跳转表，而是通过计算得到 handler 地址
imul    eax, HANDLER_STRIDE
add     eax, HANDLER_BASE
jmp     eax
```

#### 变体 2: 链式分发 (Threaded Dispatch)
```asm
; 每个 handler 末尾直接包含下一次分发逻辑
; 而非回到统一的 dispatcher
handler_vAdd:
    ; ... handler 逻辑 ...
    
    ; 内联分发
    movzx   eax, byte ptr [esi]
    add     esi, 1
    xor     al, NEW_KEY            ; 注意: key 可能变化
    jmp     dword ptr [handler_table + eax*4]
```

#### 变体 3: 间接分发 (Indirect Threading)
```asm
; handler 地址存储在 bytecode 中而非跳转表
mov     eax, dword ptr [esi]      ; 直接读取 handler 地址
add     esi, 4
xor     eax, KEY
jmp     eax
```

## VMContext 结构

### 虚拟寄存器映射

VMP 使用虚拟寄存器组模拟 x86 寄存器，但映射关系是随机的：

```c
struct VMContext {
    uint32_t vRegs[16];     // 虚拟寄存器组 (数量可变)
    uint32_t vFlags;        // 虚拟标志位
    uint8_t* VIP;           // 虚拟指令指针 (通常用 ESI)
    uint32_t* VSP;          // 虚拟栈指针 (通常用 EBP)
    uint32_t decryptKey;    // 当前解密密钥
};

// VMP 2.x 典型映射 (每次保护都不同):
// vRegs[0]  → 映射到 EAX
// vRegs[5]  → 映射到 ECX
// vRegs[3]  → 映射到 ESP
// vRegs[11] → 映射到 EFLAGS
// ... (随机化)
```

### 虚拟栈

```
高地址
┌──────────────┐
│ 原始寄存器值  │ ← pushad/pushfd 保存
├──────────────┤
│ 返回地址      │
├──────────────┤
│ VM 临时数据   │
│     ...      │
│              │
│              │ ← VSP (Virtual Stack Pointer)
├──────────────┤
│ 虚拟寄存器组  │ ← VMContext base
│  vRegs[0]    │
│  vRegs[1]    │
│  ...         │
│  vRegs[N]    │
└──────────────┘
低地址
```

## Bytecode 编码方案

### 指令格式

```
┌────────┬──────────┬───────────┬───────────┐
│ Opcode │ Operand1 │ Operand2  │ Extension │
│ 1 byte │ 1-4 byte │ 0-4 byte  │ 0-N byte  │
└────────┴──────────┴───────────┴───────────┘
```

### 加密层次

```
Layer 1: Opcode XOR with rolling key
Layer 2: Operand encryption (XOR/ADD/ROL with key derived from opcode)
Layer 3: Key update after each instruction (key = f(key, opcode))
```

### VMP 3.x 密钥滚动

```python
# 伪代码: VMP 3.x 密钥更新机制
def update_key(current_key, opcode):
    key = current_key ^ opcode
    key = rotate_left(key, 7)
    key = key + 0xDEADBEEF  # 常量因实例而异
    key = key ^ rotate_right(key, 13)
    return key
```

## VM 嵌套 (VMP 3.x)

VMP 3.x 支持 VM 嵌套——被虚拟化的代码中可以再进入另一层 VM：

```
原始代码 → VM_Level1(bytecode1) 
              → VM_Level2(bytecode2)
                  → VM_Level3(bytecode3)
                  ← 返回 Level2
              ← 返回 Level1
         ← 返回原始流
```

每层 VM 可能使用不同的：
- Handler 集合
- 加密密钥
- 分发模式
- 寄存器映射

这极大增加了分析复杂度。

## 关键识别特征

### 如何识别 VMP 保护的代码

1. **VMEntry 特征**: `push imm32; pushad; pushfd` 序列
2. **Dispatcher 特征**: 循环中的 `movzx + xor + jmp [table]` 模式
3. **Handler 区域**: 大量相似结构的小代码块
4. **字符串特征**: `.vmp0`/`.vmp1` section 名
5. **导入特征**: 大量 `VirtualAlloc`/`VirtualProtect` 调用
6. **代码特征**: 高密度的 `push/pop` 操作，stack-based computation
