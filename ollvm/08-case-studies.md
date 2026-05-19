# OLLVM 解混淆实战案例

## 案例 1: Android SO 的控制流平坦化解除

### 场景
某 Android 即时通讯 APP 的 `libcrypto_engine.so`，核心加密函数被 OLLVM 控制流平坦化保护。

### 分析流程

#### Step 1: 识别混淆

```
IDA 加载 SO 文件 → 定位关键函数 (通过 JNI 注册表或导出符号)
→ Graph View 观察到典型的星形 CFG
→ 确认为控制流平坦化
```

#### Step 2: 定位关键组件

```python
# IDA Script: 分析 ARM 平坦化函数
def analyze_arm_flattened(func_addr):
    func = idaapi.get_func(func_addr)
    cfg = idaapi.FlowChart(func)
    
    # 找 dispatcher (入边最多的块)
    block_info = []
    for block in cfg:
        in_degree = len(list(block.preds()))
        out_degree = len(list(block.succs()))
        block_info.append({
            'addr': block.start_ea,
            'end': block.end_ea,
            'in_degree': in_degree,
            'out_degree': out_degree,
        })
    
    # dispatcher: 入度最高
    dispatcher = max(block_info, key=lambda x: x['in_degree'])
    print(f"Dispatcher: {dispatcher['addr']:#x} "
          f"(in={dispatcher['in_degree']}, out={dispatcher['out_degree']})")
    
    # 找状态变量
    # ARM 中通常是: LDR Rn, [SP, #offset] → CMP Rn, #imm
    block = idaapi.get_func(dispatcher['addr'])
    for addr in range(dispatcher['addr'], dispatcher['end']):
        mnem = idc.print_insn_mnem(addr)
        if mnem in ('CMP', 'SUBS'):
            state_reg = idc.print_operand(addr, 0)
            print(f"State compare at {addr:#x}: {state_reg}")
```

#### Step 3: 使用 deflat 工具

```bash
# 使用 deflat (基于 angr)
python3 deflat.py \
    -f libcrypto_engine.so \
    --addr 0x1234 \
    --arch arm \
    -o libcrypto_engine_deobf.so

# deflat 会:
# 1. 自动识别 dispatcher 和状态变量
# 2. 符号执行恢复 block 转换关系
# 3. Patch 二进制恢复直接跳转
```

#### Step 4: Frida 验证

```javascript
// 验证解混淆结果是否正确
var original = Module.findBaseAddress('libcrypto_engine.so');
var funcOffset = 0x1234;

// 在原始函数上 Hook，记录输入输出
Interceptor.attach(original.add(funcOffset), {
    onEnter: function(args) {
        this.input = Memory.readByteArray(args[0], 32);
        console.log('Input: ' + hexdump(this.input));
    },
    onLeave: function(retval) {
        console.log('Output: ' + retval);
    }
});

// 加载解混淆后的 SO，比较结果
// 如果输入输出一致，则解混淆正确
```

## 案例 2: 虚假控制流 + 字符串加密

### 场景
某金融 APP 的 native 库，登录密钥生成函数被 BCF + 字符串加密保护。

### Step 1: 字符串解密

```javascript
// Frida: 在 constructor 执行后 dump 解密字符串
Java.perform(function() {
    // 等待 SO 加载
    var mod = Process.findModuleByName('libsecure.so');
    if (!mod) {
        Interceptor.attach(Module.findExportByName(null, 'android_dlopen_ext'), {
            onLeave: function() {
                mod = Process.findModuleByName('libsecure.so');
                if (mod) {
                    dumpStrings(mod);
                }
            }
        });
    } else {
        dumpStrings(mod);
    }
});

function dumpStrings(mod) {
    // .rodata section 中的字符串应该已经被 constructor 解密
    var sections = mod.enumerateRanges('r--');
    sections.forEach(function(range) {
        var start = range.base;
        var size = range.size;
        
        // 扫描 printable ASCII
        try {
            var data = Memory.readByteArray(start, Math.min(size, 0x10000));
            var bytes = new Uint8Array(data);
            var str = '';
            
            for (var i = 0; i < bytes.length; i++) {
                if (bytes[i] >= 0x20 && bytes[i] < 0x7F) {
                    str += String.fromCharCode(bytes[i]);
                } else if (str.length >= 4) {
                    console.log('[STR] ' + start.add(i - str.length) + ': ' + str);
                    str = '';
                } else {
                    str = '';
                }
            }
        } catch(e) {}
    });
}
```

### Step 2: BCF 消除

```python
# IDA Script: 半自动消除 BCF
import idaapi
import idc
from z3 import *

def auto_remove_bcf(func_addr):
    """自动识别并消除 BCF"""
    func = idaapi.get_func(func_addr)
    patches = []
    
    for block in idaapi.FlowChart(func):
        # 获取块的最后一条指令
        last_insn = idc.prev_head(block.end_ea)
        mnem = idc.print_insn_mnem(last_insn)
        
        if mnem not in ('BNE', 'BEQ', 'JNZ', 'JZ', 'JE', 'JNE'):
            continue
        
        # 回溯查找不透明谓词计算
        cmp_addr = find_preceding_compare(last_insn)
        if not cmp_addr:
            continue
        
        # 提取比较的表达式
        expr = extract_expression(cmp_addr)
        
        # 使用 Z3 验证
        result = verify_opaque_predicate(expr)
        
        if result == 'always_true':
            # 条件永真 → 分支永不跳转 → NOP 掉条件跳转
            patches.append({
                'addr': last_insn,
                'type': 'nop',
                'reason': f'Opaque predicate (always true) at {cmp_addr:#x}'
            })
        elif result == 'always_false':
            # 条件永假 → 分支永远跳转 → 改为无条件跳转
            target = idc.get_operand_value(last_insn, 0)
            patches.append({
                'addr': last_insn,
                'type': 'unconditional_jmp',
                'target': target,
                'reason': f'Opaque predicate (always false) at {cmp_addr:#x}'
            })
    
    # 应用 patches
    for patch in patches:
        print(f"Patching {patch['addr']:#x}: {patch['reason']}")
        apply_patch(patch)
    
    return patches
```

## 案例 3: 综合混淆 (CFF + BCF + SUB)

### 场景
某游戏反作弊模块的关键检测函数，同时使用了三种 OLLVM 混淆。

### 系统化解混淆流程

```python
# 完整的解混淆流程脚本
class GameACDeobfuscator:
    def __init__(self, binary_path, func_addr):
        self.binary = binary_path
        self.func_addr = func_addr
    
    def phase1_reconnaissance(self):
        """侦察阶段: 识别混淆类型和范围"""
        print("=== Phase 1: Reconnaissance ===")
        
        # 1. 函数大小分析
        func = idaapi.get_func(self.func_addr)
        size = func.end_ea - func.start_ea
        print(f"Function size: {size} bytes")
        
        # 2. 基本块数量
        cfg = idaapi.FlowChart(func)
        blocks = list(cfg)
        print(f"Basic blocks: {len(blocks)}")
        
        # 3. 检测 CFF
        max_in_degree = max(len(list(b.preds())) for b in blocks)
        if max_in_degree > 5:
            print(f"[DETECTED] CFF - dispatcher in_degree={max_in_degree}")
            self.has_cff = True
        
        # 4. 检测 BCF
        opaque_count = self.count_opaque_predicates()
        if opaque_count > 0:
            print(f"[DETECTED] BCF - {opaque_count} opaque predicates")
            self.has_bcf = True
        
        # 5. 检测 SUB
        sub_count = self.count_substitutions()
        if sub_count > 0:
            print(f"[DETECTED] SUB - {sub_count} instruction substitutions")
            self.has_sub = True
    
    def phase2_bcf_removal(self):
        """第二阶段: 消除虚假控制流"""
        print("\n=== Phase 2: BCF Removal ===")
        
        if not self.has_bcf:
            print("No BCF detected, skipping")
            return
        
        # 1. 识别所有不透明谓词
        predicates = identify_opaque_predicates(self.func_addr)
        
        # 2. 验证并消除
        for pred in predicates:
            if verify_with_z3(pred):
                patch_opaque_predicate(pred)
                print(f"  Patched: {pred['addr']:#x}")
        
        # 3. 删除死代码块
        dead = find_unreachable_blocks(self.func_addr)
        nop_blocks(dead)
        print(f"  Removed {len(dead)} dead blocks")
    
    def phase3_sub_restoration(self):
        """第三阶段: 还原指令替换"""
        print("\n=== Phase 3: Instruction Substitution Restoration ===")
        
        if not self.has_sub:
            print("No SUB detected, skipping")
            return
        
        # 使用 D-810 或自定义规则
        # D-810 在 Hex-Rays Microcode 层面处理更高效
        print("  Apply D-810 MBA simplification rules...")
    
    def phase4_cff_deflattening(self):
        """第四阶段: 解控制流平坦化"""
        print("\n=== Phase 4: CFF Deflattening ===")
        
        if not self.has_cff:
            print("No CFF detected, skipping")
            return
        
        # 使用 deflat / angr
        transitions = symbolic_execution_deflat(self.binary, self.func_addr)
        
        # 修补跳转
        for src, targets in transitions.items():
            patch_transitions(src, targets)
            print(f"  {src:#x} → {[f'{t:#x}' for t in targets]}")
    
    def phase5_verification(self):
        """第五阶段: 验证"""
        print("\n=== Phase 5: Verification ===")
        
        # 1. 重新反编译
        cfunc = idaapi.decompile(self.func_addr)
        if cfunc:
            print("Decompilation successful")
            print(str(cfunc))
        
        # 2. 动态验证
        print("Run dynamic verification with Frida...")
```

## 案例 4: Hikari 增强混淆

### 场景
使用 Hikari (OLLVM 增强版) 保护的 iOS 应用，包含字符串加密 + 间接跳转 + 函数包装。

### 字符串加密 (Hikari 特有)

```python
# Hikari 字符串加密的特征:
# 1. .init_array 中有大量解密函数
# 2. 每个字符串有独立的解密函数
# 3. 解密函数模式: XOR with rolling key

def find_hikari_string_decryptors(binary):
    """查找 Hikari 字符串解密函数"""
    import lief
    
    binary = lief.parse(binary)
    init_array = binary.get_section('.init_array')
    
    if not init_array:
        return []
    
    data = bytes(init_array.content)
    ptr_size = 8 if binary.header.identity_class == lief.ELF.ELF_CLASS.CLASS64 else 4
    
    decryptors = []
    for i in range(0, len(data), ptr_size):
        addr = int.from_bytes(data[i:i+ptr_size], 'little')
        if addr != 0 and is_decrypt_function(addr):
            decryptors.append(addr)
    
    return decryptors
```

### 间接跳转解混淆

```python
# Hikari 间接跳转混淆
# 原始: call func_A
# 混淆后:
#   mov rax, [rip + offset]   ; 加载加密的函数指针
#   xor rax, KEY              ; 解密
#   call rax                  ; 间接调用

def resolve_indirect_calls(func_addr):
    """解析 Hikari 间接调用"""
    results = []
    
    func = idaapi.get_func(func_addr)
    for addr in idautils.Heads(func.start_ea, func.end_ea):
        mnem = idc.print_insn_mnem(addr)
        
        if mnem in ('call', 'BLX', 'BL'):
            op_type = idc.get_operand_type(addr, 0)
            
            if op_type == idc.o_reg:
                # 间接调用 → 回溯分析
                target = trace_indirect_target(addr)
                if target:
                    results.append({
                        'call_addr': addr,
                        'target': target,
                        'name': idc.get_name(target, 0)
                    })
                    # 添加注释
                    idc.set_cmt(addr, f"→ {idc.get_name(target, 0)}", 0)
    
    return results
```

## 案例 5: CTF 中的 OLLVM 题目

### 典型 CTF 逆向题

```
题目: 一个 ELF 程序要求输入 flag，经过混淆函数校验后输出 Correct/Wrong

分析策略:
1. 运行程序，确认是 flag checker
2. IDA 加载，定位 main → check_flag 函数
3. 观察到 OLLVM 混淆
4. 解混淆或直接分析算法
```

### 快速解题策略

```python
# CTF 快速策略: 不需要完全解混淆
# 方法 1: 符号执行直接求解

import angr
import claripy

def solve_flag(binary_path, flag_len=32):
    proj = angr.Project(binary_path)
    
    # 符号化输入
    flag = claripy.BVS('flag', flag_len * 8)
    
    state = proj.factory.entry_state(
        stdin=angr.SimFileStream(name='stdin', content=flag)
    )
    
    # 约束: flag 为可打印字符
    for i in range(flag_len):
        byte = flag.get_byte(i)
        state.solver.add(byte >= 0x20)
        state.solver.add(byte <= 0x7e)
    
    simgr = proj.factory.simulation_manager(state)
    
    # 探索到 "Correct" 输出
    simgr.explore(
        find=lambda s: b"Correct" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong" in s.posix.dumps(1)
    )
    
    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(flag, cast_to=bytes)
        print(f"Flag: {solution.decode()}")
        return solution
    
    return None

# 方法 2: 约束提取 (对小规模混淆有效)
def extract_constraints(binary_path, check_func_addr):
    """提取校验函数的约束，用 Z3 求解"""
    proj = angr.Project(binary_path)
    
    state = proj.factory.blank_state(addr=check_func_addr)
    
    # 符号化参数
    input_buf = claripy.BVS('input', 256)
    state.memory.store(0x600000, input_buf)
    state.regs.rdi = 0x600000  # 第一个参数
    
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=success_addr, avoid=fail_addr)
    
    if simgr.found:
        constraints = simgr.found[0].solver.constraints
        # 导出约束，用 Z3 求解
        from z3 import *
        z3_solver = Solver()
        for c in constraints:
            z3_solver.add(claripy_to_z3(c))
        
        if z3_solver.check() == sat:
            model = z3_solver.model()
            print(f"Solution: {model}")
```

### 方法 3: Side-Channel (对抗强混淆)

```python
# 利用执行时间/指令数量进行侧信道分析
import subprocess
import time

def side_channel_solve(binary_path, flag_prefix='', charset=None):
    """基于指令计数的侧信道攻击"""
    if charset is None:
        charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}'
    
    flag = flag_prefix
    
    while True:
        best_char = None
        best_count = 0
        
        for c in charset:
            candidate = flag + c
            
            # 使用 perf 或 PIN 计数指令
            result = subprocess.run(
                ['perf', 'stat', '-e', 'instructions:u', 
                 '-x', ',', binary_path],
                input=candidate.encode(),
                capture_output=True, timeout=5
            )
            
            # 解析指令计数
            stderr = result.stderr.decode()
            count = int(stderr.split(',')[0])
            
            if count > best_count:
                best_count = count
                best_char = c
        
        flag += best_char
        print(f"Flag so far: {flag} (instructions: {best_count})")
        
        if best_char == '}':
            break
    
    return flag
```
