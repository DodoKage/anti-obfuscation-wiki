# VMP Handler 分析方法

## Handler 识别与分类

### Handler 类型总览

VMP 的 handler 实现了一套完整的虚拟指令集，类似于 RISC 架构：

```
┌─────────────────────────────────────────────────────────┐
│                    VMP Handler 分类                       │
├──────────────┬──────────────────────────────────────────┤
│ 栈操作        │ vPush, vPop, vPushImm, vPushReg         │
├──────────────┼──────────────────────────────────────────┤
│ 算术运算      │ vAdd, vSub, vMul, vDiv, vNeg            │
├──────────────┼──────────────────────────────────────────┤
│ 逻辑运算      │ vAnd, vOr, vXor, vNot, vNand, vNor      │
├──────────────┼──────────────────────────────────────────┤
│ 移位运算      │ vShl, vShr, vSar, vRol, vRor            │
├──────────────┼──────────────────────────────────────────┤
│ 内存访问      │ vLoad (读内存), vStore (写内存)           │
├──────────────┼──────────────────────────────────────────┤
│ 控制流        │ vJmp, vJcc (条件跳转), vCall, vRet       │
├──────────────┼──────────────────────────────────────────┤
│ 上下文操作    │ vRegRead, vRegWrite, vFlagRead           │
├──────────────┼──────────────────────────────────────────┤
│ 系统交互      │ vSyscall, vCpuid, vRdtsc                │
├──────────────┼──────────────────────────────────────────┤
│ VM 控制       │ vNop, vVMExit                            │
└──────────────┴──────────────────────────────────────────┘
```

### 核心 Handler 实现

#### vPush (压栈)

将值压入虚拟栈：

```asm
; vPush immediate (32-bit)
handler_vPushImm32:
    mov     eax, dword ptr [esi]    ; 从 bytecode 读取立即数
    add     esi, 4                   ; VIP += 4
    xor     eax, KEY                 ; 解密立即数
    sub     ebp, 4                   ; VSP -= 4
    mov     [ebp], eax               ; 写入虚拟栈
    ; ... dispatch next ...

; vPush register
handler_vPushReg:
    movzx   eax, byte ptr [esi]     ; 读取虚拟寄存器索引
    add     esi, 1
    mov     eax, [edi + eax*4]      ; 从 VMContext 读取寄存器值
    sub     ebp, 4
    mov     [ebp], eax
    ; ... dispatch next ...
```

#### vPop (出栈)

```asm
; vPop to register
handler_vPopReg:
    movzx   eax, byte ptr [esi]     ; 读取目标虚拟寄存器索引
    add     esi, 1
    mov     ecx, [ebp]              ; 读取虚拟栈顶
    add     ebp, 4                   ; VSP += 4
    mov     [edi + eax*4], ecx      ; 写入虚拟寄存器
    ; ... dispatch next ...
```

#### vAdd (加法)

VMP 的算术运算基于栈操作：

```asm
; vAdd: stack[top-1] = stack[top-1] + stack[top]
handler_vAdd:
    mov     eax, [ebp]              ; 取栈顶 (操作数2)
    add     ebp, 4                   ; pop
    add     [ebp], eax               ; 加到新栈顶 (操作数1)
    pushfd                           ; 保存真实 EFLAGS
    pop     dword ptr [edi + FLAGS_OFFSET]  ; 存到虚拟 FLAGS
    ; ... dispatch next ...
```

#### vNand (与非)

VMP 的一个关键特性：用 NAND 门实现所有逻辑运算：

```asm
; vNand: ~(a & b)
handler_vNand:
    mov     eax, [ebp]
    add     ebp, 4
    and     eax, [ebp]              ; a & b
    not     eax                      ; ~(a & b)
    mov     [ebp], eax
    pushfd
    pop     dword ptr [edi + FLAGS_OFFSET]
    ; ... dispatch next ...
```

利用 NAND 的完备性：
```
AND(a,b) = NAND(NAND(a,b), NAND(a,b))
OR(a,b)  = NAND(NAND(a,a), NAND(b,b))
XOR(a,b) = NAND(NAND(NAND(a,a),b), NAND(a,NAND(b,b)))
NOT(a)   = NAND(a,a)
```

#### vLoad / vStore (内存访问)

```asm
; vLoad: 读取内存
handler_vLoad32:
    mov     eax, [ebp]              ; 取地址
    mov     eax, [eax]              ; 读取内存
    mov     [ebp], eax               ; 结果存回栈
    ; ... dispatch next ...

; vStore: 写入内存
handler_vStore32:
    mov     eax, [ebp]              ; 取地址
    add     ebp, 4
    mov     ecx, [ebp]              ; 取数据
    add     ebp, 4
    mov     [eax], ecx              ; 写入内存
    ; ... dispatch next ...
```

#### vJcc (条件跳转)

```asm
; 条件跳转基于虚拟 EFLAGS
handler_vJcc:
    mov     eax, [ebp]              ; 目标地址1 (条件成立)
    add     ebp, 4
    mov     ecx, [ebp]              ; 目标地址2 (条件不成立)  
    add     ebp, 4
    mov     edx, [ebp]              ; 虚拟 EFLAGS
    add     ebp, 4
    test    edx, FLAG_MASK          ; 检查条件标志
    cmovnz  ecx, eax               ; 条件选择
    mov     esi, ecx                ; 更新 VIP
    ; ... dispatch next ...
```

## Handler 分析策略

### 方法 1: 静态模式匹配

识别 handler 的固定模式：

```python
# IDA Python: 识别 VMP handler 模式
import idautils
import idc

def find_handlers(dispatcher_addr):
    handlers = {}
    
    for xref in idautils.CodeRefsFrom(dispatcher_addr, 0):
        handler_type = classify_handler(xref)
        if handler_type:
            handlers[xref] = handler_type
    
    return handlers

def classify_handler(addr):
    """根据指令模式分类 handler"""
    insns = get_instructions(addr, 20)
    
    # vAdd 特征: add [ebp], eax; pushfd
    if has_pattern(insns, ['add [ebp*]', 'pushfd']):
        return 'vAdd'
    
    # vNand 特征: and + not
    if has_pattern(insns, ['and', 'not', 'pushfd']):
        return 'vNand'
    
    # vPush 特征: sub ebp, 4; mov [ebp], *
    if has_pattern(insns, ['sub ebp*', 'mov [ebp*]']):
        return 'vPush'
    
    # ... 更多模式
    return None
```

### 方法 2: 动态 Trace

通过执行 trace 记录 handler 调用序列：

```python
# x64dbg 脚本: Trace VMP handler 执行
import x64dbg

class VMTracer:
    def __init__(self, dispatcher_addr, handler_table):
        self.dispatcher = dispatcher_addr
        self.handler_table = handler_table
        self.trace = []
    
    def on_breakpoint(self, addr):
        if addr == self.dispatcher:
            # 记录当前 opcode 和虚拟栈状态
            opcode = read_byte(get_reg('esi'))
            vsp = get_reg('ebp')
            stack_top = read_dword(vsp)
            
            self.trace.append({
                'vip': get_reg('esi'),
                'opcode': opcode,
                'handler': self.handler_table.get(opcode, 'unknown'),
                'vsp': vsp,
                'stack_top': stack_top,
            })
    
    def dump_trace(self):
        for entry in self.trace:
            print(f"VIP={entry['vip']:08X} OP={entry['opcode']:02X} "
                  f"Handler={entry['handler']} "
                  f"VSP={entry['vsp']:08X} Top={entry['stack_top']:08X}")
```

### 方法 3: 符号执行辅助

使用 Triton/angr 进行符号执行来理解 handler 语义：

```python
from triton import *

def analyze_handler_semantics(handler_addr, handler_size):
    ctx = TritonContext(ARCH.X86)
    
    # 符号化虚拟栈和寄存器
    ctx.symbolizeMemory(MemoryAccess(VSP_ADDR, 4), "stack_top")
    ctx.symbolizeMemory(MemoryAccess(VSP_ADDR + 4, 4), "stack_second")
    ctx.symbolizeRegister(ctx.registers.esi, "VIP")
    
    # 模拟执行 handler
    pc = handler_addr
    for _ in range(100):
        inst = Instruction(pc, read_bytes(pc, 16))
        ctx.processing(inst)
        
        if is_dispatch_jump(inst):
            break
        pc = ctx.getConcreteRegisterValue(ctx.registers.eip)
    
    # 提取语义: 分析虚拟栈变化
    result = ctx.getSymbolicMemoryValue(MemoryAccess(VSP_ADDR, 4))
    print(f"Handler semantics: stack_top = {result}")
```

## Handler 变异识别

### VMP 3.x Handler 混淆技术

1. **Handler 复制**: 同一语义的 handler 存在多个不同实现
2. **垃圾指令**: handler 内插入大量无效计算
3. **等价变换**: `add` 用 `sub neg` 替代
4. **handler 分裂**: 一个 handler 拆成多个基本块
5. **handler 合并**: 多个简单 handler 合并为一个

### 去除 Handler 混淆

```python
# 使用 Miasm 进行 handler 简化
from miasm.analysis.simplifier import IRCFGSimplifierCommon
from miasm.expression.simplifications import expr_simp

def simplify_handler(handler_ir):
    """简化混淆的 handler IR"""
    simplifier = IRCFGSimplifierCommon(handler_ir)
    
    # 1. 死代码消除
    simplifier.deadcode_elimination()
    
    # 2. 常量折叠
    simplifier.constant_folding()
    
    # 3. 表达式简化
    for block in handler_ir.blocks:
        for assignblk in block:
            for dst, src in assignblk.items():
                simplified = expr_simp(src)
                assignblk[dst] = simplified
    
    return handler_ir
```

## 自动化 Handler 识别框架

### 基于语义哈希的识别

```python
import hashlib

class HandlerIdentifier:
    def __init__(self):
        self.known_handlers = self._load_signatures()
    
    def identify(self, handler_addr):
        """基于行为语义识别 handler"""
        # 1. 提取语义特征
        features = self._extract_features(handler_addr)
        
        # 2. 计算语义哈希
        sem_hash = self._semantic_hash(features)
        
        # 3. 匹配已知签名
        return self.known_handlers.get(sem_hash, 'unknown')
    
    def _extract_features(self, addr):
        """提取 handler 行为特征"""
        return {
            'stack_delta': self._calc_stack_delta(addr),     # 栈指针变化
            'memory_reads': self._count_mem_reads(addr),     # 内存读次数
            'memory_writes': self._count_mem_writes(addr),   # 内存写次数
            'flag_update': self._check_flag_update(addr),    # 是否更新标志
            'vip_delta': self._calc_vip_delta(addr),         # VIP 变化量
            'operation': self._identify_operation(addr),     # 核心运算
        }
    
    def _semantic_hash(self, features):
        feature_str = str(sorted(features.items()))
        return hashlib.md5(feature_str.encode()).hexdigest()
```
