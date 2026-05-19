# 符号执行在代码保护对抗中的应用

## 符号执行基础

### 核心思想

```
传统执行: 输入具体值 → 沿确定路径执行 → 得到具体输出
符号执行: 输入符号变量 → 探索所有可能路径 → 得到路径条件和符号输出

具体执行:  f(5) = 10
符号执行:  f(x) = 2x when x > 0
                 = -x when x <= 0
```

### 符号执行引擎对比

| 引擎 | 语言 | IR | 强项 | 弱项 |
|------|------|-----|------|------|
| angr | Python | VEX IR | 全自动分析、大型二进制 | 性能较慢 |
| Triton | Python/C++ | 自有 IR | 精确符号追踪、API友好 | 路径探索需手动 |
| Miasm | Python | 自有 IR | IR 简化强大 | 文档较少 |
| KLEE | C++ | LLVM IR | 源码级分析 | 仅支持 LLVM bitcode |
| Manticore | Python | 自有 | 智能合约分析 | 通用二进制支持有限 |
| Z3 | C++/Python | SMT-LIB | 约束求解 | 非执行引擎 |

## angr 在对抗中的应用

### 基本使用模式

```python
import angr
import claripy

proj = angr.Project('./target', auto_load_libs=False)

# 创建符号状态
state = proj.factory.entry_state()

# 或从特定地址开始
state = proj.factory.blank_state(addr=0x401000)

# 符号化寄存器
sym_input = claripy.BVS('input', 32)
state.regs.eax = sym_input

# 符号化内存
sym_buf = claripy.BVS('buffer', 8 * 256)
state.memory.store(0x600000, sym_buf)

# 创建模拟管理器
simgr = proj.factory.simulation_manager(state)

# 探索路径
simgr.explore(
    find=0x401100,   # 目标地址
    avoid=[0x401200] # 避免地址
)

# 提取解
if simgr.found:
    found_state = simgr.found[0]
    solution = found_state.solver.eval(sym_input)
    print(f"Solution: {solution}")
```

### VMP 对抗中的应用

```python
class VMPSymbolicAnalyzer:
    def __init__(self, proj, vm_entry, vm_exit):
        self.proj = proj
        self.vm_entry = vm_entry
        self.vm_exit = vm_exit
    
    def analyze_vm_semantics(self):
        """通过符号执行提取 VM 语义"""
        state = self.proj.factory.blank_state(addr=self.vm_entry)
        
        # 符号化所有通用寄存器 (VM 的输入)
        sym_regs = {}
        for reg_name in ['eax', 'ecx', 'edx', 'ebx', 'esi', 'edi']:
            sym = claripy.BVS(f'input_{reg_name}', 32)
            setattr(state.regs, reg_name, sym)
            sym_regs[reg_name] = sym
        
        # 符号化内存参数
        for i, offset in enumerate([0x8, 0xC, 0x10]):
            sym_arg = claripy.BVS(f'arg_{i}', 32)
            state.memory.store(
                state.regs.ebp + offset, sym_arg, endness='Iend_LE'
            )
        
        # Hook VM Dispatcher 以加速执行
        self._hook_dispatcher(state)
        
        # 执行直到 VM Exit
        simgr = self.proj.factory.simulation_manager(state)
        simgr.explore(find=self.vm_exit)
        
        if simgr.found:
            result_state = simgr.found[0]
            
            # 提取输出寄存器的符号表达式
            output = {}
            for reg_name in ['eax', 'ecx', 'edx', 'ebx']:
                expr = getattr(result_state.regs, reg_name)
                simplified = claripy.simplify(expr)
                output[reg_name] = str(simplified)
            
            return output
    
    def _hook_dispatcher(self, state):
        """Hook dispatcher 以避免路径爆炸"""
        @self.proj.hook(self.dispatcher_addr, length=self.dispatcher_size)
        def dispatcher_hook(state):
            # 读取 opcode
            vip = state.regs.esi
            opcode = state.memory.load(vip, 1)
            
            # 对每个已知的 handler，直接应用语义
            # 这比让 angr 逐条执行 handler 快得多
            for known_opcode, semantic_func in self.handler_semantics.items():
                if state.solver.is_true(opcode == known_opcode):
                    semantic_func(state)
                    return
```

### OLLVM 对抗中的应用

```python
class OLLVMSymbolicDeflattener:
    """基于符号执行的 OLLVM 解平坦化"""
    
    def __init__(self, proj, func_addr):
        self.proj = proj
        self.func_addr = func_addr
        self.cfg = proj.analyses.CFGFast(
            regions=[(func_addr, func_addr + 0x10000)]
        )
        self.func = self.cfg.functions[func_addr]
    
    def find_state_variable(self):
        """定位状态变量"""
        # 分析 dispatcher 中的 comparison 指令
        dispatcher = self.find_dispatcher()
        block = self.proj.factory.block(dispatcher)
        
        for stmt in block.vex.statements:
            if hasattr(stmt, 'data'):
                if hasattr(stmt.data, 'op') and 'Cmp' in str(stmt.data.op):
                    # 找到比较操作，提取被比较的变量
                    return self.extract_state_var(stmt)
    
    def recover_all_transitions(self):
        """恢复所有基本块的转换关系"""
        dispatcher = self.find_dispatcher()
        real_blocks = self.find_real_blocks()
        state_var = self.find_state_variable()
        
        transitions = {}
        
        for block_addr in real_blocks:
            # 为每个块创建符号状态
            state = self.proj.factory.blank_state(addr=block_addr)
            
            # 符号化非状态变量的寄存器和内存
            for reg in ['eax', 'ecx', 'edx', 'ebx']:
                setattr(state.regs, reg, claripy.BVS(f'{reg}_{block_addr:#x}', 32))
            
            # 步进执行到 dispatcher
            simgr = self.proj.factory.simulation_manager(state)
            
            # 使用 step 而非 explore，精确控制执行
            while simgr.active:
                simgr.step()
                
                # 过滤到达 dispatcher 的状态
                at_dispatcher = [s for s in simgr.active 
                                if s.addr == dispatcher]
                not_at_dispatcher = [s for s in simgr.active 
                                    if s.addr != dispatcher]
                
                for s in at_dispatcher:
                    # 提取状态变量的值
                    state_val = s.memory.load(state_var, 4, endness='Iend_LE')
                    
                    if state_val.symbolic:
                        # 条件分支: 有多个可能值
                        possible_values = s.solver.eval_upto(state_val, 5)
                        for val in possible_values:
                            target = self.state_value_to_block(val)
                            if target:
                                transitions.setdefault(block_addr, set()).add(target)
                    else:
                        # 无条件跳转: 唯一目标
                        val = s.solver.eval(state_val)
                        target = self.state_value_to_block(val)
                        if target:
                            transitions.setdefault(block_addr, set()).add(target)
                
                simgr._stashes['active'] = not_at_dispatcher
                
                # 超时保护
                if simgr.step_count > 1000:
                    break
        
        return {k: list(v) for k, v in transitions.items()}
```

## Triton 精确符号追踪

```python
from triton import *

class TritonVMAnalyzer:
    def __init__(self, arch=ARCH.X86):
        self.ctx = TritonContext(arch)
        self.ctx.setMode(MODE.ALIGNED_MEMORY, True)
        self.ctx.setMode(MODE.AST_OPTIMIZATIONS, True)
        self.ctx.setMode(MODE.CONSTANT_FOLDING, True)
    
    def analyze_handler_precise(self, handler_bytes, handler_addr):
        """精确分析单个 handler 的符号语义"""
        # 设置内存和寄存器
        self.ctx.setConcreteMemoryAreaValue(handler_addr, handler_bytes)
        
        # 符号化虚拟栈
        for i in range(8):
            addr = 0x7FF00000 + i * 4
            self.ctx.symbolizeMemory(
                MemoryAccess(addr, 4), f"stack_{i}"
            )
        
        # 符号化寄存器
        self.ctx.symbolizeRegister(
            self.ctx.registers.ebp, "VSP"
        )
        self.ctx.setConcreteRegisterValue(
            self.ctx.registers.ebp, 0x7FF00000
        )
        
        self.ctx.symbolizeRegister(
            self.ctx.registers.esi, "VIP"
        )
        
        # 逐条执行
        ip = handler_addr
        executed = 0
        while executed < 100:
            opcodes = self.ctx.getConcreteMemoryAreaValue(ip, 16)
            inst = Instruction(ip, bytes(opcodes))
            
            if not self.ctx.processing(inst):
                break
            
            # 检测分发跳转 (handler 结束)
            if inst.getType() in [OPCODE.X86.JMP, OPCODE.X86.RET]:
                break
            
            ip = int(self.ctx.getConcreteRegisterValue(self.ctx.registers.eip))
            executed += 1
        
        # 提取语义效果
        effects = {}
        
        # 检查虚拟栈的变化
        vsp = self.ctx.getSymbolicRegister(self.ctx.registers.ebp)
        if vsp:
            vsp_ast = vsp.getAst()
            simplified = self.ctx.simplify(vsp_ast, True)
            effects['vsp_delta'] = str(simplified)
        
        # 检查栈顶值
        stack_top = self.ctx.getSymbolicMemory(0x7FF00000)
        if stack_top:
            effects['stack_top'] = str(self.ctx.simplify(stack_top.getAst(), True))
        
        return effects
    
    def trace_vm_execution(self, binary_data, base_addr, entry_point, max_steps=100000):
        """完整 trace VM 执行"""
        self.ctx.setConcreteMemoryAreaValue(base_addr, binary_data)
        self.ctx.setConcreteRegisterValue(self.ctx.registers.eip, entry_point)
        
        trace = []
        ip = entry_point
        
        for step in range(max_steps):
            opcodes = self.ctx.getConcreteMemoryAreaValue(ip, 16)
            inst = Instruction(ip, bytes(opcodes))
            self.ctx.processing(inst)
            
            trace.append({
                'addr': ip,
                'disasm': str(inst),
                'symbolic_regs': self._get_symbolic_state()
            })
            
            ip = int(self.ctx.getConcreteRegisterValue(self.ctx.registers.eip))
        
        return trace
```

## Z3 约束求解

```python
from z3 import *

class ConstraintSolver:
    """用于解混淆的约束求解工具"""
    
    @staticmethod
    def verify_opaque_predicate(expr_func):
        """验证表达式是否为不透明谓词"""
        x, y = BitVecs('x y', 32)
        
        s = Solver()
        s.add(Not(expr_func(x, y)))
        
        if s.check() == unsat:
            return 'always_true'
        
        s2 = Solver()
        s2.add(expr_func(x, y))
        
        if s2.check() == unsat:
            return 'always_false'
        
        return 'variable'
    
    @staticmethod
    def solve_state_mapping(encrypted_states, decrypt_func):
        """求解加密状态变量的映射关系"""
        state = BitVec('state', 32)
        s = Solver()
        
        mappings = {}
        for encrypted in encrypted_states:
            s.push()
            s.add(decrypt_func(state) == encrypted)
            
            if s.check() == sat:
                model = s.model()
                original = model[state].as_long()
                mappings[encrypted] = original
            
            s.pop()
        
        return mappings
    
    @staticmethod
    def simplify_mba_z3(expr_func, num_vars=2):
        """使用 Z3 简化 MBA 表达式"""
        if num_vars == 1:
            x = BitVec('x', 32)
            candidates = [
                ('x', x),
                ('~x', ~x),
                ('x + 1', x + 1),
                ('x - 1', x - 1),
                ('x * 2', x * 2),
                ('-x', -x),
            ]
            
            for name, candidate in candidates:
                s = Solver()
                s.add(expr_func(x) != candidate)
                if s.check() == unsat:
                    return name
        
        elif num_vars == 2:
            x, y = BitVecs('x y', 32)
            candidates = [
                ('x + y', x + y),
                ('x - y', x - y),
                ('x ^ y', x ^ y),
                ('x & y', x & y),
                ('x | y', x | y),
                ('x * y', x * y),
                ('~(x & y)', ~(x & y)),
                ('~(x | y)', ~(x | y)),
            ]
            
            for name, candidate in candidates:
                s = Solver()
                s.add(expr_func(x, y) != candidate)
                if s.check() == unsat:
                    return name
        
        return None
```

## 符号执行的局限与对策

### 路径爆炸

```python
# 对策 1: 路径裁剪
simgr.explore(
    find=target,
    avoid=avoid_addrs,
    step_func=lambda sm: sm.drop(
        stash='active',
        filter_func=lambda s: s.history.depth > MAX_DEPTH
    )
)

# 对策 2: 状态合并
simgr.use_technique(angr.exploration_techniques.Veritesting())

# 对策 3: 选择性符号化 (混合执行)
# 只符号化关键变量，其余使用具体值
state.options.add(angr.options.LAZY_SOLVES)
```

### 内存建模

```python
# 对策: 限制符号化内存范围
# 只符号化已知的输入缓冲区
state.memory.store(input_addr, sym_input)
# 其余内存保持具体值
```

### 性能优化

```python
# 1. 使用 Unicorn 引擎加速具体执行
state.options.add(angr.options.UNICORN)

# 2. Hook 库函数
proj.hook_symbol('strlen', angr.SIM_PROCEDURES['libc']['strlen']())
proj.hook_symbol('strcmp', angr.SIM_PROCEDURES['libc']['strcmp']())

# 3. 缓存约束求解结果
state.options.add(angr.options.CONSTRAINT_TRACKING_IN_SOLVER)
```
