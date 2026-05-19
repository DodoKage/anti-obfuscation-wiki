# 污点分析在代码保护对抗中的应用

## 污点分析基础

### 核心概念

```
Source (污点源): 数据进入的位置 (用户输入、网络数据、文件读取)
Sink   (汇聚点): 敏感操作的位置 (系统调用、密钥比较、校验函数)
Taint  (污点):   标记数据是否受 Source 影响
传播规则: 定义污点如何通过运算传播

例:
  x = read_input()     ← Source: x 被标记为 tainted
  y = x + 5            ← 传播: y 也被标记为 tainted
  z = 10               ← 未污染
  if (y == KEY)         ← Sink: tainted 数据到达校验点
```

### 传播规则

```
赋值:   dst = src          → taint(dst) = taint(src)
加法:   dst = a + b        → taint(dst) = taint(a) ∪ taint(b)
移位:   dst = a << b       → taint(dst) = taint(a) ∪ taint(b)
逻辑:   dst = a & b        → taint(dst) = taint(a) ∪ taint(b)
条件:   if (tainted_val)   → 两个分支都可能被影响 (隐式流)
内存:   [addr] = val       → taint(mem[addr]) = taint(val)
        val = [addr]       → taint(val) = taint(mem[addr])
                              如果 addr 也是 tainted → taint(val) 更复杂
```

## 在 VMP 对抗中的应用

### 追踪虚拟化代码中的数据流

```python
class VMTaintTracker:
    """追踪 VMP 中输入数据的传播路径"""
    
    def __init__(self):
        self.taint_map = {}  # {location: set of taint sources}
        self.taint_log = []  # 传播日志
    
    def mark_source(self, location, source_name):
        """标记污点源"""
        self.taint_map[location] = {source_name}
    
    def propagate(self, handler_type, src_locs, dst_loc):
        """根据 handler 类型传播污点"""
        combined_taint = set()
        for loc in src_locs:
            if loc in self.taint_map:
                combined_taint |= self.taint_map[loc]
        
        if combined_taint:
            self.taint_map[dst_loc] = combined_taint
            self.taint_log.append({
                'handler': handler_type,
                'sources': src_locs,
                'dest': dst_loc,
                'taint': combined_taint,
            })
    
    def analyze_vm_trace(self, trace):
        """分析 VM trace 中的数据流"""
        for entry in trace:
            handler = entry['handler_type']
            
            if handler == 'vPushReg':
                # 从寄存器到栈
                reg = f"vReg[{entry['operand']}]"
                stack = f"vStack[{entry['vsp']}]"
                self.propagate('vPushReg', [reg], stack)
            
            elif handler == 'vPopReg':
                stack = f"vStack[{entry['vsp']}]"
                reg = f"vReg[{entry['operand']}]"
                self.propagate('vPopReg', [stack], reg)
            
            elif handler == 'vAdd':
                s1 = f"vStack[{entry['vsp']}]"
                s2 = f"vStack[{entry['vsp'] + 4}]"
                result = f"vStack[{entry['vsp'] + 4}]"
                self.propagate('vAdd', [s1, s2], result)
            
            elif handler == 'vLoad':
                addr_loc = f"vStack[{entry['vsp']}]"
                mem_loc = f"mem[{entry['effective_addr']}]"
                result = f"vStack[{entry['vsp']}]"
                self.propagate('vLoad', [mem_loc], result)
            
            elif handler == 'vStore':
                addr_loc = f"vStack[{entry['vsp']}]"
                data_loc = f"vStack[{entry['vsp'] + 4}]"
                mem_loc = f"mem[{entry['effective_addr']}]"
                self.propagate('vStore', [data_loc], mem_loc)
    
    def find_tainted_sinks(self):
        """找出哪些关键位置受输入影响"""
        sinks = []
        for loc, taint in self.taint_map.items():
            if 'user_input' in taint:
                if self.is_sensitive_location(loc):
                    sinks.append((loc, taint))
        return sinks
```

### 使用 Triton 进行动态污点分析

```python
from triton import *

class TritonTaintAnalyzer:
    def __init__(self):
        self.ctx = TritonContext(ARCH.X86)
        self.ctx.setMode(MODE.TAINT_THROUGH_POINTERS, True)
    
    def mark_input_tainted(self, addr, size):
        """标记输入为污点"""
        for i in range(size):
            self.ctx.taintMemory(MemoryAccess(addr + i, 1))
    
    def check_taint_at_sink(self, sink_addr):
        """检查 sink 点处哪些值是 tainted"""
        tainted_regs = []
        for reg in [self.ctx.registers.eax, self.ctx.registers.ecx,
                    self.ctx.registers.edx, self.ctx.registers.ebx]:
            if self.ctx.isRegisterTainted(reg):
                tainted_regs.append(reg.getName())
        return tainted_regs
    
    def trace_with_taint(self, code_bytes, base_addr, 
                         input_addr, input_size, max_steps=10000):
        """带污点追踪的执行 trace"""
        self.ctx.setConcreteMemoryAreaValue(base_addr, code_bytes)
        self.mark_input_tainted(input_addr, input_size)
        
        ip = base_addr
        taint_events = []
        
        for step in range(max_steps):
            opcodes = self.ctx.getConcreteMemoryAreaValue(ip, 16)
            inst = Instruction(ip, bytes(opcodes))
            self.ctx.processing(inst)
            
            # 记录污点传播事件
            if inst.isTainted():
                taint_events.append({
                    'addr': ip,
                    'disasm': str(inst),
                    'tainted_regs': [
                        r.getName() for r in inst.getWrittenRegisters()
                        if self.ctx.isRegisterTainted(r[0])
                    ],
                })
            
            ip = int(self.ctx.getConcreteRegisterValue(self.ctx.registers.eip))
        
        return taint_events
```

## 在 OLLVM 对抗中的应用

### 区分真实逻辑和虚假代码

```python
class OLLVMTaintFilter:
    """使用污点分析过滤 OLLVM 中的虚假代码"""
    
    def __init__(self, proj, func_addr):
        self.proj = proj
        self.func_addr = func_addr
    
    def identify_real_blocks(self, input_params):
        """
        通过污点分析识别真正处理输入的基本块
        BCF 产生的虚假块不会处理真实输入 → 不会被污染
        """
        state = self.proj.factory.blank_state(addr=self.func_addr)
        
        # 符号化+污点化输入参数
        for i, param in enumerate(input_params):
            sym = claripy.BVS(f'param_{i}', param['size'] * 8)
            if param['type'] == 'reg':
                setattr(state.regs, param['name'], sym)
            elif param['type'] == 'mem':
                state.memory.store(param['addr'], sym)
        
        # 执行并追踪
        simgr = self.proj.factory.simulation_manager(state)
        
        tainted_blocks = set()
        
        def step_callback(simgr):
            for s in simgr.active:
                block_addr = s.addr
                # 检查当前块是否使用了 tainted 数据
                block = self.proj.factory.block(block_addr)
                for stmt in block.vex.statements:
                    if self._uses_symbolic_data(s, stmt):
                        tainted_blocks.add(block_addr)
            return simgr
        
        simgr.explore(step_func=step_callback)
        
        return tainted_blocks
    
    def _uses_symbolic_data(self, state, stmt):
        """检查语句是否使用了符号化数据"""
        # 检查读取的表达式是否包含符号变量
        if hasattr(stmt, 'data'):
            try:
                data = state.solver.eval(stmt.data)
                return stmt.data.symbolic
            except:
                pass
        return False
```

### 追踪状态变量的来源

```python
def trace_state_variable_origin(func_addr, state_var_offset):
    """
    追踪 CFF 中状态变量的值来自哪里
    有助于理解原始的分支条件
    """
    taint_map = {}
    
    for block in get_case_blocks(func_addr):
        # 找到状态变量的赋值语句
        for insn in get_block_instructions(block):
            if writes_to_state_var(insn, state_var_offset):
                # 回溯: 值是常量还是来自计算?
                source = backtrack_value(insn)
                
                if source['type'] == 'constant':
                    taint_map[block] = {
                        'next_state': source['value'],
                        'condition': 'unconditional',
                    }
                elif source['type'] == 'conditional':
                    taint_map[block] = {
                        'true_state': source['true_value'],
                        'false_state': source['false_value'],
                        'condition': source['condition'],
                        'condition_depends_on': source['taint_sources'],
                    }
    
    return taint_map
```

## Frida 动态污点分析

```javascript
// Frida: 简单的动态污点追踪
'use strict';

class TaintTracker {
    constructor() {
        this.taintedAddrs = new Set();
        this.taintLog = [];
    }
    
    markTainted(addr, size, source) {
        for (let i = 0; i < size; i++) {
            this.taintedAddrs.add(addr.add(i).toString());
        }
        this.taintLog.push({
            event: 'source',
            addr: addr.toString(),
            size: size,
            source: source
        });
    }
    
    isTainted(addr) {
        return this.taintedAddrs.has(addr.toString());
    }
    
    propagate(srcAddr, dstAddr, size) {
        let propagated = false;
        for (let i = 0; i < size; i++) {
            if (this.taintedAddrs.has(srcAddr.add(i).toString())) {
                this.taintedAddrs.add(dstAddr.add(i).toString());
                propagated = true;
            }
        }
        if (propagated) {
            this.taintLog.push({
                event: 'propagate',
                src: srcAddr.toString(),
                dst: dstAddr.toString(),
                size: size
            });
        }
    }
}

// 使用示例: 追踪用户输入在混淆函数中的传播
var tracker = new TaintTracker();

// 标记输入缓冲区
var inputBuf = ptr('0x600000');
tracker.markTainted(inputBuf, 256, 'user_input');

// Hook 关键比较操作
Interceptor.attach(ptr('0x401234'), {
    onEnter: function(args) {
        if (tracker.isTainted(args[0])) {
            console.log('[SINK] Tainted data reached comparison!');
            console.log('  Value: ' + Memory.readU32(args[0]));
        }
    }
});
```

## 污点分析的局限

| 局限 | 说明 | 缓解方案 |
|------|------|----------|
| 隐式流 | 通过控制流传播的信息 (if tainted → branch) | 追踪条件分支中的污点 |
| 过度污染 | 污点传播过于保守，几乎所有数据都被标记 | 精确的传播规则 |
| 欠污染 | 遗漏某些传播路径 | 组合静态+动态分析 |
| 性能开销 | 动态污点分析显著降低执行速度 | 限制追踪范围 |
| 指针别名 | 不同指针指向同一内存 | 结合别名分析 |
