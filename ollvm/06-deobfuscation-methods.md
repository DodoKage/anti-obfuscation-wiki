# OLLVM 综合解混淆方法

## 解混淆总体策略

```
┌────────────────────────────────────────────────────────────────┐
│                    OLLVM 解混淆工作流                           │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Step 1: 识别混淆类型                                          │
│  ├── 控制流平坦化 → 星形 CFG                                   │
│  ├── 虚假控制流   → 不透明谓词 + 死代码                         │
│  ├── 指令替换     → 异常复杂的算术表达式                        │
│  ├── 字符串加密   → 无明文字符串 + constructor 解密              │
│  └── 间接跳转     → 计算跳转地址                                │
│                                                                │
│  Step 2: 优先级排序                                            │
│  ├── 1st: 字符串解密 (获取语义信息)                             │
│  ├── 2nd: BCF 消除 (减少干扰)                                  │
│  ├── 3rd: 指令替换还原 (恢复可读性)                             │
│  └── 4th: CFF 解平坦化 (恢复控制流)                            │
│                                                                │
│  Step 3: 逐步解混淆                                            │
│  ├── 使用工具自动化处理                                        │
│  ├── 手工处理工具无法覆盖的部分                                │
│  └── 验证解混淆结果的正确性                                    │
│                                                                │
│  Step 4: 分析去混淆后的代码                                    │
│  ├── 重建 CFG                                                  │
│  ├── 反编译                                                    │
│  └── 理解算法逻辑                                              │
└────────────────────────────────────────────────────────────────┘
```

## 自动化解混淆工具

### 1. D-810 (IDA Pro 插件)

D-810 是目前最实用的 OLLVM 解混淆工具。

```
安装:
1. 下载 D-810 from GitHub
2. 复制到 IDA plugins 目录
3. 重启 IDA

功能:
- 控制流解平坦化 (CFF Unflattening)
- 不透明谓词消除
- MBA 表达式简化
- 死代码消除
- 常量折叠

使用流程:
1. 在 IDA 中打开目标二进制
2. 定位到混淆函数
3. Edit → Plugins → D-810
4. 选择适用的规则集:
   - "default": 通用 OLLVM 规则
   - "ollvm_fla": 专用于控制流平坦化
   - "ollvm_bcf": 专用于虚假控制流
5. 点击 "Start"
6. 重新按 F5 反编译查看效果
```

#### D-810 自定义规则

```python
# D-810 规则示例 (在 D-810 的规则文件中定义)
{
    "name": "custom_ollvm_opaque",
    "description": "Remove custom opaque predicates",
    "rules": [
        {
            "pattern": "x * (x + 1) & 1 == 0",
            "replacement": "true",
            "type": "opaque_predicate"
        },
        {
            "pattern": "7 * y * y - 1 != x * x",
            "replacement": "true",
            "type": "opaque_predicate"
        }
    ]
}
```

### 2. HexRaysDeob (Hex-Rays Microcode)

```python
# 基于 Hex-Rays Microcode API 的解混淆框架
import ida_hexrays

class OLLVMDeobfuscator(ida_hexrays.optblock_t):
    """在 Hex-Rays microcode 层面解混淆"""
    
    def func(self, blk):
        changed = False
        
        # 1. 消除不透明谓词
        changed |= self.remove_opaque_predicates(blk)
        
        # 2. 简化 MBA 表达式
        changed |= self.simplify_mba(blk)
        
        # 3. 解控制流平坦化
        changed |= self.unflatten(blk)
        
        return changed
    
    def remove_opaque_predicates(self, blk):
        """消除 microcode 中的不透明谓词"""
        for insn in blk:
            if insn.opcode == ida_hexrays.m_jcnd:
                if self.is_always_true(insn.l):
                    # 转为 nop (删除条件跳转)
                    insn.opcode = ida_hexrays.m_nop
                    return True
                elif self.is_always_false(insn.l):
                    # 转为无条件跳转
                    insn.opcode = ida_hexrays.m_goto
                    insn.l = insn.d  # 跳转目标
                    return True
        return False

# 注册优化器
deob = OLLVMDeobfuscator()
deob.install()
```

### 3. Miasm (框架级)

```python
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.simplifications import expr_simp

class MiasmDeobfuscator:
    def __init__(self, binary_path, arch='x86_32'):
        self.container = Container.from_stream(open(binary_path, 'rb'))
        self.machine = Machine(arch)
        self.mdis = self.machine.dis_engine(self.container.bin_stream)
    
    def deobfuscate_function(self, func_addr):
        """使用 Miasm 解混淆函数"""
        # 1. 反汇编
        asmcfg = self.mdis.dis_multiblock(func_addr)
        
        # 2. 转换为 IR
        lifter = self.machine.lifter_model_call(self.mdis.loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
        
        # 3. 符号执行简化
        sb = SymbolicExecutionEngine(lifter)
        
        # 4. 表达式简化
        for block in ircfg.blocks.values():
            for assignblk in block:
                for dst, src in assignblk.items():
                    simplified = expr_simp(src)
                    assignblk[dst] = simplified
        
        return ircfg
    
    def deflattening(self, func_addr):
        """控制流解平坦化"""
        asmcfg = self.mdis.dis_multiblock(func_addr)
        lifter = self.machine.lifter_model_call(self.mdis.loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
        
        # 识别 dispatcher
        dispatcher = self.find_dispatcher(asmcfg)
        state_var = self.find_state_variable(ircfg, dispatcher)
        
        # 对每个 case block 符号执行
        transitions = {}
        for block_addr in self.get_case_blocks(asmcfg, dispatcher):
            sb = SymbolicExecutionEngine(lifter)
            # 执行该 block
            next_state = sb.eval_updt_irblock(ircfg.get_block(block_addr))
            # 提取状态变量的值
            state_value = sb.eval_expr(state_var)
            transitions[block_addr] = state_value
        
        # 重建 CFG
        return self.rebuild_cfg(asmcfg, transitions, dispatcher)
```

### 4. angr 解混淆

```python
import angr
import claripy
from angr.analyses.decompiler.optimization_passes import OptimizationPass

class ANGRDeflattener:
    def __init__(self, binary_path):
        self.proj = angr.Project(binary_path, auto_load_libs=False)
    
    def deflat(self, func_addr):
        """angr 解控制流平坦化"""
        # 1. 构建 CFG
        cfg = self.proj.analyses.CFGFast(
            regions=[(func_addr, func_addr + 0x10000)],
            normalize=True
        )
        
        func = cfg.functions[func_addr]
        
        # 2. 识别平坦化组件
        dispatcher = self.find_dispatcher(func)
        prologue = self.find_prologue(func)
        real_blocks = self.find_real_blocks(func, dispatcher, prologue)
        state_var = self.find_state_var(func, dispatcher)
        
        # 3. 符号执行恢复转换
        transitions = {}
        for block in real_blocks:
            state = self.proj.factory.blank_state(addr=block.addr)
            
            # 设置初始状态
            for reg in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']:
                setattr(state.regs, reg, claripy.BVS(f'{reg}', 32))
            
            # 执行直到 dispatcher
            simgr = self.proj.factory.simulation_manager(state)
            simgr.explore(find=dispatcher.addr)
            
            if simgr.found:
                found = simgr.found[0]
                # 读取状态变量的值
                next_state = found.memory.load(state_var, 4, endness='Iend_LE')
                
                # 如果是具体值，直接映射
                if not next_state.symbolic:
                    concrete = found.solver.eval(next_state)
                    target = self.state_to_block(concrete, real_blocks)
                    transitions[block.addr] = [target]
                else:
                    # 条件分支: 找到所有可能的值
                    possible = found.solver.eval_upto(next_state, 10)
                    targets = [self.state_to_block(v, real_blocks) for v in possible]
                    transitions[block.addr] = targets
        
        return transitions
    
    def patch_binary(self, transitions, output_path):
        """修补二进制文件"""
        import lief
        binary = lief.parse(self.proj.filename)
        
        for src_addr, targets in transitions.items():
            if len(targets) == 1:
                # 无条件跳转: 将 jmp dispatcher 改为 jmp target
                self.patch_unconditional_jump(binary, src_addr, targets[0])
            elif len(targets) == 2:
                # 条件跳转
                self.patch_conditional_jump(binary, src_addr, targets[0], targets[1])
        
        binary.write(output_path)
```

## 手工解混淆技巧

### 技巧 1: IDA Graph View 辅助

```
1. 在 IDA 中打开 Graph View (Space)
2. 识别中心 dispatcher 节点 (入边最多)
3. 标记每个 case block 的功能
4. 追踪状态变量的赋值序列
5. 手工重建 basic block 间的关系
```

### 技巧 2: 条件断点辅助

```python
# x64dbg: 使用条件断点记录状态转换
# 在 dispatcher 处设置条件断点

# 记录状态变量值
bp dispatcher_addr
condition: log("state={[ebp-4]:x}"); false

# 运行后分析日志:
# state=A3B2C1D0 → block_entry
# state=7F8E9D0A → block_if_then
# state=1C2D3E4F → block_if_else
# state=DEADBEEF → block_if_end
```

### 技巧 3: Patching 跳过混淆

```python
# 直接 patch 掉混淆部分

# 1. 找到函数的核心逻辑块
# 2. 将 dispatcher 开头 patch 为直接跳到第一个逻辑块
# 3. 将每个逻辑块末尾的 jmp dispatcher 
#    patch 为跳到下一个逻辑块

import keystone

ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)

def patch_jump(binary, patch_addr, target_addr):
    """将指定位置 patch 为 jmp target"""
    offset = target_addr - patch_addr - 5  # 5 = jmp rel32 指令长度
    asm = f"jmp {offset}"
    encoding, count = ks.asm(asm)
    
    for i, byte in enumerate(encoding):
        binary[patch_addr + i] = byte
```

## 综合案例: 解混淆一个完整函数

### 目标函数特征

```
- 控制流平坦化 + 虚假控制流 + 指令替换
- 函数大小: 原始约 200 字节，混淆后约 5000 字节
- 20+ 个基本块
- 3 个不透明谓词
- 多处 MBA 表达式
```

### 解混淆步骤

```python
def full_deobfuscation(func_addr):
    """完整解混淆流程"""
    
    # Phase 1: 字符串解密
    decrypt_all_strings()
    
    # Phase 2: BCF 消除
    opaque_preds = identify_opaque_predicates(func_addr)
    for pred in opaque_preds:
        patch_opaque_predicate(pred)
    
    dead_blocks = find_dead_blocks(func_addr)
    remove_dead_blocks(dead_blocks)
    
    # Phase 3: 指令替换还原
    substitutions = find_substitution_patterns(func_addr)
    for sub in substitutions:
        replace_with_original(sub)
    
    # Phase 4: MBA 简化
    mba_exprs = find_mba_expressions(func_addr)
    for expr in mba_exprs:
        simplified = simplify_mba(expr)
        replace_expression(expr, simplified)
    
    # Phase 5: 控制流解平坦化
    transitions = recover_cfg_transitions(func_addr)
    patch_cfg(transitions)
    
    # Phase 6: 清理和优化
    remove_dispatcher()
    merge_adjacent_blocks()
    
    # Phase 7: 重新反编译
    redecompile(func_addr)
```

### 解混淆前后对比

```c
// 解混淆前 (IDA 反编译输出)
int __cdecl sub_401000(int a1, int a2) {
    int v2, v3, v4, v5, v6, v7, v8;
    int state = 0x1A2B3C4D;
    
    while (1) {
        switch (state) {
            case 0x1A2B3C4D:
                v2 = a1;
                if ((v2 * (v2 + 1)) % 2 == 0) // 不透明谓词
                    state = 0x5E6F7A8B;
                else
                    state = 0xDEAD0001; // 虚假路径
                break;
            case 0x5E6F7A8B:
                v3 = (~a1 & a2) | (a1 & ~a2); // x ^ y 的 SUB 替换
                v4 = ~(~a1 | ~a2);              // x & y 的 SUB 替换
                v5 = v3 + 2 * v4;               // (x^y) + 2*(x&y) = x + y
                state = 0x9CADBECF;
                break;
            // ... 更多混淆的 case ...
        }
    }
}

// 解混淆后
int __cdecl add_and_check(int x, int y) {
    int sum = x + y;
    if (sum > 100) {
        return sum * 2;
    }
    return sum;
}
```

## 自动化解混淆 Pipeline

```python
class OLLVMDeobPipeline:
    """自动化 OLLVM 解混淆管线"""
    
    def __init__(self, binary_path):
        self.binary = binary_path
        self.passes = [
            StringDecryptionPass(),
            BCFRemovalPass(),
            InstructionSubstitutionPass(),
            MBASimplificationPass(),
            CFFDeflatteningPass(),
            DeadCodeEliminationPass(),
            CFGCleanupPass(),
        ]
    
    def run(self, func_addr):
        """对指定函数运行所有解混淆 pass"""
        result = FunctionState(self.binary, func_addr)
        
        for pass_obj in self.passes:
            print(f"Running pass: {pass_obj.name}")
            changed = pass_obj.run(result)
            if changed:
                print(f"  → Changes applied")
                result.reanalyze()
            else:
                print(f"  → No changes")
        
        return result
    
    def run_all_functions(self):
        """对所有混淆函数运行解混淆"""
        obfuscated_funcs = self.detect_obfuscated_functions()
        
        for func_addr in obfuscated_funcs:
            print(f"\nDeobfuscating function at {func_addr:#x}")
            self.run(func_addr)
```
