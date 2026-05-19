# VMP 去虚拟化 (Devirtualization) 技术

## 去虚拟化概述

去虚拟化的目标是将 VMP 的虚拟指令序列还原为等价的 x86/x64 原始指令，或至少还原为可分析的中间表示 (IR)。

```
VMP Bytecode → Handler Trace → IR Lifting → Optimization → x86 Reconstruction
     ↓              ↓              ↓              ↓              ↓
  加密字节码     记录执行序列    提升为IR      简化优化       生成原始指令
```

## 方法论体系

### 方法 1: 基于 Trace 的去虚拟化

最经典、最实用的方法。

#### 步骤

```
Step 1: 定位 VMEntry/VMDispatcher/VMExit
Step 2: 在 Dispatcher 处设置 trace，记录 handler 调用序列
Step 3: 对每个 handler 进行语义分析，提取其 IR 效果
Step 4: 将 handler IR 序列组合，生成完整的执行语义
Step 5: 对 IR 进行优化简化 (常量折叠、死代码消除、强度削弱)
Step 6: 从优化后的 IR 重新生成 x86 指令
```

#### 实现框架

```python
class TraceBasedDevirtualizer:
    def __init__(self, binary_path):
        self.binary = binary_path
        self.trace = []
        self.ir_sequence = []
    
    def step1_locate_vm_components(self):
        """定位 VM 组件"""
        self.vm_entry = self.find_vm_entry()
        self.dispatcher = self.find_dispatcher()
        self.handlers = self.find_handlers()
        self.vm_exit = self.find_vm_exit()
    
    def step2_trace_execution(self, input_args):
        """动态 trace 记录 handler 序列"""
        tracer = DynamicTracer(self.binary)
        tracer.set_breakpoint(self.dispatcher)
        
        self.trace = tracer.run(input_args)
        # trace = [(handler_addr, vip, vsp, context), ...]
    
    def step3_lift_to_ir(self):
        """将每个 handler 调用提升为 IR"""
        for entry in self.trace:
            handler_ir = self.analyze_handler(entry.handler_addr)
            # 绑定具体操作数
            concrete_ir = handler_ir.bind(entry.operands)
            self.ir_sequence.append(concrete_ir)
    
    def step4_optimize_ir(self):
        """优化 IR 序列"""
        optimized = self.ir_sequence
        
        # Pass 1: 常量折叠 (Constant Folding)
        optimized = constant_folding(optimized)
        
        # Pass 2: 死代码消除 (Dead Code Elimination)
        optimized = dead_code_elimination(optimized)
        
        # Pass 3: 复写传播 (Copy Propagation)
        optimized = copy_propagation(optimized)
        
        # Pass 4: VM 特定优化
        optimized = remove_vm_overhead(optimized)  # 移除 VM 调度开销
        optimized = collapse_nand_chains(optimized) # 折叠 NAND 链
        optimized = restore_flags(optimized)        # 还原标志位计算
        
        self.ir_sequence = optimized
    
    def step5_generate_x86(self):
        """从 IR 生成 x86"""
        codegen = X86CodeGenerator()
        for ir_inst in self.ir_sequence:
            x86_inst = codegen.lower(ir_inst)
            codegen.emit(x86_inst)
        
        return codegen.get_binary()
```

### 方法 2: 基于符号执行的去虚拟化

使用符号执行引擎追踪数据流。

```python
import angr
import claripy

class SymbolicDevirtualizer:
    def __init__(self, binary_path, vm_entry):
        self.proj = angr.Project(binary_path)
        self.vm_entry = vm_entry
    
    def devirtualize(self):
        # 1. 创建符号状态
        state = self.proj.factory.blank_state(addr=self.vm_entry)
        
        # 符号化输入参数
        arg1 = claripy.BVS("arg1", 32)
        arg2 = claripy.BVS("arg2", 32)
        state.regs.eax = arg1
        state.regs.ecx = arg2
        
        # 2. 符号执行直到 VMExit
        simgr = self.proj.factory.simulation_manager(state)
        simgr.explore(find=self.vm_exit_addrs)
        
        # 3. 提取符号表达式
        if simgr.found:
            found_state = simgr.found[0]
            
            # 分析输出寄存器的符号表达式
            eax_expr = found_state.regs.eax
            ecx_expr = found_state.regs.ecx
            
            # 简化表达式
            simplified_eax = claripy.simplify(eax_expr)
            
            print(f"EAX = {simplified_eax}")  
            # 输出类似: EAX = arg1 + arg2 (如果原始代码是 add)
            
            return self.expr_to_x86(simplified_eax)
```

#### 符号执行的挑战

- **路径爆炸**: VM Dispatcher 循环导致大量路径
- **内存模型**: 虚拟栈操作需要精确建模
- **性能**: 复杂 VM 嵌套时极其缓慢

#### 缓解策略

```python
# 1. 限制路径深度
simgr.explore(find=target, num_find=1, 
              step_func=lambda sm: sm.drop(stash='active', 
                                           filter_func=lambda s: s.history.depth > 10000))

# 2. Hook dispatcher，直接使用 handler 语义
@proj.hook(dispatcher_addr, length=dispatcher_size)
def hook_dispatcher(state):
    opcode = state.memory.load(state.regs.esi, 1)
    # 直接根据 opcode 应用语义效果
    handler_semantic = get_handler_semantic(opcode)
    handler_semantic.apply(state)

# 3. Concretize VIP (虚拟指令指针不需要符号化)
state.options.add(angr.options.LAZY_SOLVES)
```

### 方法 3: 基于抽象解释的去虚拟化

利用抽象解释框架进行值域分析和语义恢复。

```python
class AbstractDevirtualizer:
    def __init__(self):
        self.abstract_state = AbstractState()
    
    def analyze_handler_abstract(self, handler):
        """对 handler 进行抽象解释"""
        # 定义抽象域
        # - 区间域 (Interval Domain): 追踪值范围
        # - 符号域 (Symbolic Domain): 追踪符号关系
        # - 标签域 (Tag Domain): 追踪数据来源
        
        for inst in handler.instructions:
            self.abstract_state.transfer(inst)
        
        return self.abstract_state.get_effects()
```

### 方法 4: 基于模式匹配的快速恢复

对于 VMP 2.x 等较老版本，可以通过模式匹配快速恢复：

```python
# Handler 序列模式 → 原始指令映射
PATTERNS = {
    # vPushReg(R1) + vPushReg(R2) + vAdd + vPopReg(R1) 
    # → add R1, R2
    ('vPushReg', 'vPushReg', 'vAdd', 'vPopReg'): 
        lambda ops: f"add {ops[3]}, {ops[1]}",
    
    # vPushImm(IMM) + vPushReg(R1) + vAdd + vPopReg(R1)
    # → add R1, IMM
    ('vPushImm', 'vPushReg', 'vAdd', 'vPopReg'):
        lambda ops: f"add {ops[3]}, {ops[0]}",
    
    # vPushReg(R1) + vPushReg(R1) + vNand + vPopReg(R1)
    # → not R1
    ('vPushReg', 'vPushReg', 'vNand', 'vPopReg'):
        lambda ops: f"not {ops[0]}" if ops[0] == ops[1] else None,
    
    # vPushMem(ADDR) + vPopReg(R1) → mov R1, [ADDR]
    ('vPushMem', 'vPopReg'): 
        lambda ops: f"mov {ops[1]}, [{ops[0]}]",
}

def pattern_match_devirt(handler_sequence):
    """模式匹配去虚拟化"""
    result = []
    i = 0
    while i < len(handler_sequence):
        matched = False
        # 尝试最长匹配
        for length in range(6, 0, -1):
            pattern_key = tuple(h.type for h in handler_sequence[i:i+length])
            if pattern_key in PATTERNS:
                operands = [h.operand for h in handler_sequence[i:i+length]]
                x86_inst = PATTERNS[pattern_key](operands)
                if x86_inst:
                    result.append(x86_inst)
                    i += length
                    matched = True
                    break
        if not matched:
            result.append(f"; unknown: {handler_sequence[i]}")
            i += 1
    return result
```

## NAND 链还原

VMP 大量使用 NAND 实现逻辑运算，还原算法：

```python
class NandChainReducer:
    """将 NAND 链还原为标准逻辑运算"""
    
    def reduce(self, expr):
        # NAND(a, a) → NOT(a)
        if self.is_nand(expr) and expr.left == expr.right:
            return ('NOT', expr.left)
        
        # NAND(NAND(a,b), NAND(a,b)) → AND(a,b)
        if (self.is_nand(expr) and 
            expr.left == expr.right and 
            self.is_nand(expr.left)):
            return ('AND', expr.left.left, expr.left.right)
        
        # NAND(NAND(a,a), NAND(b,b)) → OR(a,b)
        if (self.is_nand(expr) and
            self.is_nand(expr.left) and self.is_nand(expr.right) and
            expr.left.left == expr.left.right and
            expr.right.left == expr.right.right):
            return ('OR', expr.left.left, expr.right.left)
        
        # 更复杂的 XOR 模式
        # NAND(NAND(NAND(a,a),b), NAND(a,NAND(b,b))) → XOR(a,b)
        if self.matches_xor_pattern(expr):
            a, b = self.extract_xor_operands(expr)
            return ('XOR', a, b)
        
        return expr
```

## 控制流恢复

### 基本块重建

```python
def rebuild_cfg(devirtualized_trace):
    """从去虚拟化的指令流重建控制流图"""
    cfg = ControlFlowGraph()
    current_block = BasicBlock()
    
    for inst in devirtualized_trace:
        current_block.add(inst)
        
        if inst.is_branch():
            cfg.add_block(current_block)
            
            if inst.is_conditional():
                # 条件分支: 创建两条边
                true_target = inst.true_target
                false_target = inst.false_target
                cfg.add_edge(current_block, true_target, 'true')
                cfg.add_edge(current_block, false_target, 'false')
            else:
                # 无条件跳转
                cfg.add_edge(current_block, inst.target)
            
            current_block = BasicBlock()
    
    if current_block.instructions:
        cfg.add_block(current_block)
    
    return cfg
```

### 循环检测与还原

```python
def detect_loops(cfg):
    """检测并还原循环结构"""
    dominators = compute_dominators(cfg)
    back_edges = []
    
    for block in cfg.blocks:
        for succ in cfg.successors(block):
            if dominators[block].contains(succ):
                back_edges.append((block, succ))
    
    loops = []
    for tail, header in back_edges:
        loop_body = find_natural_loop(cfg, header, tail)
        loops.append(Loop(header, tail, loop_body))
    
    return loops
```

## 去虚拟化质量评估

### 评估指标

| 指标 | 说明 | 理想值 |
|------|------|--------|
| 指令恢复率 | 成功映射回 x86 的指令比例 | > 90% |
| 语义正确性 | 去虚拟化代码与原始功能一致 | 100% |
| 代码膨胀率 | 恢复代码大小 / 原始代码大小 | < 2x |
| 控制流完整性 | CFG 中基本块和边的完整度 | > 95% |

### 验证方法

1. **差分测试**: 对同一输入，比较原始程序和去虚拟化结果的输出
2. **符号等价性检查**: 验证关键表达式的符号等价
3. **覆盖率分析**: 确保所有 handler 都被覆盖到
