# OLLVM 解混淆工具集

## 专用解混淆工具

### 1. D-810

- **平台**: IDA Pro 插件
- **仓库**: github.com/joydo/d810
- **功能**: 
  - Hex-Rays Microcode 层面的解混淆
  - 不透明谓词识别与消除
  - MBA 表达式简化
  - 控制流解平坦化
  - 可自定义规则
- **支持**: x86/x64, ARM/ARM64
- **评价**: 目前最实用的 IDA 解混淆插件

### 2. OLLVM-Deobfuscator (利用符号执行)

- **仓库**: github.com/pcy190/ollvm-deobfuscator
- **原理**: 基于 angr 的符号执行解平坦化
- **特点**: 自动化程度高

### 3. deflat (基于 angr)

- **仓库**: github.com/cq674350529/deflat
- **原理**: angr + 符号执行解控制流平坦化
- **使用**:
```bash
python deflat.py -f binary --addr 0x401000
```
- **输出**: 修补后的二进制文件

### 4. obpo (OLLVM Block Patching and Optimization)

- **仓库**: github.com/obpo-project/obpo-plugin
- **平台**: IDA Pro 插件
- **功能**: 
  - 基于模拟执行的解平坦化
  - 支持 Unicorn Engine 后端
  - 交互式解混淆

### 5. Egalito

- **仓库**: github.com/columbia/egalito
- **类型**: 二进制重写框架
- **功能**: 
  - ELF 二进制的反汇编和重组装
  - 可用于解混淆后重建二进制

### 6. SATURN

- **仓库**: github.com/pcy190/saturn
- **原理**: 基于 Triton 的通用去混淆框架
- **支持**: OLLVM + VMP

### 7. SiMBA / SSPAM

- **用途**: MBA 表达式简化
- **原理**: 线性代数方法求解 MBA 等价简单表达式
- **论文**: "Software Protection with Obfuscation and Encryption"

## 通用分析框架

### IDA Pro 生态

#### Hex-Rays Microcode API

```python
# Microcode 解混淆框架模板
import ida_hexrays

class DeobfuscatorBase(ida_hexrays.optinsn_t):
    """Microcode 指令级优化器"""
    
    def func(self, blk, ins, optflags):
        # 在 maturity level MMAT_GLBOPT1 或更高时生效
        if blk.mba.maturity < ida_hexrays.MMAT_GLBOPT1:
            return 0
        
        return self.optimize_instruction(blk, ins)
    
    def optimize_instruction(self, blk, ins):
        raise NotImplementedError

class DeobfuscatorBlockLevel(ida_hexrays.optblock_t):
    """Microcode 基本块级优化器"""
    
    def func(self, blk):
        return self.optimize_block(blk)
    
    def optimize_block(self, blk):
        raise NotImplementedError

# 注册
deob_insn = MyInsnDeobfuscator()
deob_insn.install()

deob_blk = MyBlockDeobfuscator()
deob_blk.install()
```

#### genmc (查看 Microcode)

```python
# 查看 Hex-Rays Microcode 的各个阶段
import ida_hexrays

def dump_microcode(func_addr, maturity=ida_hexrays.MMAT_GENERATED):
    """转储指定成熟度级别的 microcode"""
    hf = ida_hexrays.hexrays_failure_t()
    mbr = ida_hexrays.mba_ranges_t()
    pfn = ida_funcs.get_func(func_addr)
    mbr.ranges.push_back(ida_range.range_t(pfn.start_ea, pfn.end_ea))
    
    mba = ida_hexrays.gen_microcode(
        mbr, hf, None, 
        ida_hexrays.DECOMP_NO_WAIT, maturity
    )
    
    if mba:
        # 打印每个基本块
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            print(f"\n=== Block {i} (serial={blk.serial}) ===")
            insn = blk.head
            while insn:
                print(f"  {insn.dstr()}")
                insn = insn.next
```

### Ghidra 脚本

```java
// Ghidra: OLLVM 解混淆辅助脚本
import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;

public class OLLVMDeobfHelper extends GhidraScript {
    
    @Override
    protected void run() throws Exception {
        // 获取反编译器
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        // 反编译目标函数
        Function func = getFunctionAt(askAddress("Function addr", ""));
        DecompileResults results = decomp.decompileFunction(func, 60, monitor);
        
        if (results.decompileCompleted()) {
            HighFunction hf = results.getHighFunction();
            
            // 分析 P-Code 操作
            Iterator<PcodeOpAST> ops = hf.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                
                // 查找条件分支
                if (op.getOpcode() == PcodeOp.CBRANCH) {
                    analyzeBranch(op);
                }
                
                // 查找 switch/indirect jump
                if (op.getOpcode() == PcodeOp.BRANCHIND) {
                    analyzeDispatcher(op);
                }
            }
        }
    }
    
    private void analyzeBranch(PcodeOpAST op) {
        Varnode condition = op.getInput(1);
        // 检查条件是否为不透明谓词
        println("Branch condition: " + condition.toString());
    }
}
```

### Binary Ninja

```python
# Binary Ninja: OLLVM 解混淆
from binaryninja import *

class OLLVMDeobfuscation(PluginCommand):
    @staticmethod
    def deflat_function(bv, func):
        """解控制流平坦化"""
        mlil = func.medium_level_il
        
        # 1. 找 dispatcher
        dispatcher = None
        max_refs = 0
        for block in mlil:
            refs = len(list(block.incoming_edges))
            if refs > max_refs:
                max_refs = refs
                dispatcher = block
        
        if not dispatcher:
            log_error("Cannot find dispatcher")
            return
        
        # 2. 分析状态变量
        state_var = None
        for insn in dispatcher:
            if isinstance(insn, MediumLevelILSwitch):
                state_var = insn.condition
                break
            if isinstance(insn, MediumLevelILIf):
                # 可能是 if-else chain 而非 switch
                state_var = find_compared_var(insn)
                break
        
        log_info(f"Dispatcher: {dispatcher.start}")
        log_info(f"State var: {state_var}")
        
        # 3. 符号执行或模式匹配恢复转换
        # ...

PluginCommand.register_for_function(
    "OLLVM\\Deflattening", 
    "Remove CFF", 
    OLLVMDeobfuscation.deflat_function
)
```

## 动态分析工具

### Frida 辅助解混淆

```javascript
// Frida: 追踪 OLLVM 平坦化函数的真实执行路径
'use strict';

function traceOLLVM(funcAddr, stateVarOffset) {
    var base = Module.findBaseAddress('libtarget.so');
    var target = base.add(funcAddr);
    
    var visited = new Set();
    var transitions = [];
    
    Interceptor.attach(target, {
        onEnter: function(args) {
            this.lastState = null;
            
            // Hook 每个基本块的入口
            // 通过监控状态变量的变化来记录转换
            var stateAddr = this.context.sp.add(stateVarOffset);
            
            // 使用 Stalker 进行精细追踪
            Stalker.follow(this.threadId, {
                transform: function(iterator) {
                    var instruction;
                    while ((instruction = iterator.next()) !== null) {
                        // 记录每条指令
                        iterator.keep();
                        
                        // 检测状态变量写入
                        if (instruction.mnemonic === 'mov' && 
                            instruction.operands[0].type === 'mem') {
                            iterator.putCallout(function(context) {
                                var state = Memory.readU32(
                                    context.sp.add(stateVarOffset)
                                );
                                if (!visited.has(state)) {
                                    visited.add(state);
                                    console.log('State: 0x' + state.toString(16));
                                }
                            });
                        }
                    }
                }
            });
        },
        onLeave: function(retval) {
            Stalker.unfollow(this.threadId);
            console.log('Visited states: ' + visited.size);
        }
    });
}
```

### Unicorn Engine 辅助

```python
from unicorn import *
from unicorn.arm_const import *
import struct

class OLLVMEmulator:
    """使用 Unicorn 模拟执行 OLLVM 混淆函数"""
    
    def __init__(self, binary_data, arch='arm'):
        if arch == 'arm':
            self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
            self.pc_reg = UC_ARM_REG_PC
            self.sp_reg = UC_ARM_REG_SP
        elif arch == 'x86':
            self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
            self.pc_reg = UC_X86_REG_EIP
            self.sp_reg = UC_X86_REG_ESP
        
        # 映射内存
        self.base = 0x10000
        self.uc.mem_map(self.base, 0x100000)
        self.uc.mem_map(0x7F000000, 0x100000)  # 栈
        self.uc.mem_write(self.base, binary_data)
        
        self.uc.reg_write(self.sp_reg, 0x7F080000)
        
        self.block_trace = []
    
    def trace_blocks(self, func_offset, func_size):
        """记录基本块执行序列"""
        func_addr = self.base + func_offset
        
        self.uc.hook_add(UC_HOOK_BLOCK, self._block_hook,
                        begin=func_addr, end=func_addr + func_size)
        
        try:
            self.uc.emu_start(func_addr, func_addr + func_size, 
                            timeout=10*1000000)
        except UcError as e:
            print(f"Emulation error: {e}")
        
        return self.block_trace
    
    def _block_hook(self, uc, address, size, user_data):
        self.block_trace.append(address - self.base)
```

## 学术工具与研究实现

### 1. Tigress (混淆器 — 用于研究)

```
Tigress 不是解混淆工具，而是一个学术级混淆器
用途: 生成标准测试样本，评估解混淆工具效果
支持: C 语言
混淆类型: 比 OLLVM 更丰富 (虚拟化、JIT、合并函数等)
```

### 2. QSynth

- **论文**: "QSynth: A Program Synthesis based approach for Binary Code Deobfuscation"
- **原理**: 使用程序合成 (Program Synthesis) 从 I/O 样本中重建简单表达式
- **适用**: MBA 表达式简化

### 3. Syntia

- **论文**: "Syntia: Synthesizing the Semantics of Obfuscated Code"
- **原理**: 基于蒙特卡洛树搜索 (MCTS) 的程序合成
- **适用**: VM handler 语义恢复、MBA 简化

### 4. VMAttack

- **平台**: IDA Pro 插件
- **功能**: 
  - 动态分析虚拟化代码
  - Trace 记录和分析
  - 基本的去虚拟化

## 工具选择矩阵

| 混淆类型 | 推荐工具 | 备选方案 |
|----------|---------|---------|
| 控制流平坦化 (CFF) | D-810, deflat | angr, Miasm |
| 虚假控制流 (BCF) | D-810, IDA Script | Z3, Ghidra |
| 指令替换 (SUB) | D-810, MBARewriter | SSPAM, SiMBA |
| MBA 表达式 | SiMBA, QSynth | 真值表穷举 |
| 字符串加密 | FLOSS, Frida | Unicorn, IDA Script |
| 间接跳转 | IDA Script, BN Plugin | Frida trace |
| 综合混淆 | D-810 + 手工 | angr pipeline |
| Android SO | Frida + IDA | JEB, Ghidra |
