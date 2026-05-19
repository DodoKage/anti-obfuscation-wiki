# 控制流平坦化 (CFF) 深度分析

## 平坦化实现原理

### LLVM IR 层面的变换

```
原始 LLVM IR:

define i32 @foo(i32 %a, i32 %b) {
entry:
  %cmp = icmp sgt i32 %a, 0
  br i1 %cmp, label %if.then, label %if.else

if.then:
  %add = add i32 %a, %b
  br label %if.end

if.else:
  %sub = sub i32 %a, %b
  br label %if.end

if.end:
  %result = phi i32 [ %add, %if.then ], [ %sub, %if.else ]
  ret i32 %result
}
```

```
平坦化后的 LLVM IR (概念):

define i32 @foo(i32 %a, i32 %b) {
entry:
  %state = alloca i32
  store i32 STATE_ENTRY, i32* %state        ; 初始状态
  br label %dispatcher

dispatcher:
  %cur_state = load i32, i32* %state
  switch i32 %cur_state, label %default [
    i32 STATE_ENTRY,   label %block_entry
    i32 STATE_IF_THEN, label %block_if_then
    i32 STATE_IF_ELSE, label %block_if_else
    i32 STATE_IF_END,  label %block_if_end
  ]

block_entry:
  %cmp = icmp sgt i32 %a, 0
  %next = select i1 %cmp, i32 STATE_IF_THEN, i32 STATE_IF_ELSE
  store i32 %next, i32* %state
  br label %dispatcher

block_if_then:
  %add = add i32 %a, %b
  store i32 %add, i32* %result_slot
  store i32 STATE_IF_END, i32* %state
  br label %dispatcher

block_if_else:
  %sub = sub i32 %a, %b
  store i32 %sub, i32* %result_slot
  store i32 STATE_IF_END, i32* %state
  br label %dispatcher

block_if_end:
  %result = load i32, i32* %result_slot
  ret i32 %result

default:
  unreachable
}
```

### 编译到汇编后的表现

```asm
; x86 平坦化后的典型汇编
foo:
    push    ebp
    mov     ebp, esp
    sub     esp, 0x10
    
    ; 初始化状态变量
    mov     dword ptr [ebp-4], 0xA3B2C1D0    ; state = ENTRY_HASH
    
dispatcher:
    mov     eax, [ebp-4]                      ; 加载 state
    
    ; 状态比较链 (或 switch table)
    cmp     eax, 0xA3B2C1D0
    je      block_entry
    cmp     eax, 0x7F8E9D0A
    je      block_if_then
    cmp     eax, 0x1C2D3E4F
    je      block_if_else
    cmp     eax, 0xDEADBEEF
    je      block_if_end
    jmp     dispatcher                        ; 默认: 回到 dispatcher
    
block_entry:
    mov     eax, [ebp+8]                      ; a
    test    eax, eax
    jg      .set_then
    mov     dword ptr [ebp-4], 0x1C2D3E4F    ; state = IF_ELSE
    jmp     dispatcher
.set_then:
    mov     dword ptr [ebp-4], 0x7F8E9D0A    ; state = IF_THEN
    jmp     dispatcher
    
block_if_then:
    mov     eax, [ebp+8]
    add     eax, [ebp+0xC]
    mov     [ebp-8], eax                      ; result
    mov     dword ptr [ebp-4], 0xDEADBEEF    ; state = IF_END
    jmp     dispatcher
    
block_if_else:
    mov     eax, [ebp+8]
    sub     eax, [ebp+0xC]
    mov     [ebp-8], eax
    mov     dword ptr [ebp-4], 0xDEADBEEF
    jmp     dispatcher
    
block_if_end:
    mov     eax, [ebp-8]
    leave
    ret
```

## 平坦化变体

### 变体 1: 嵌套 Switch

```
多层嵌套的 switch-case:
switch (state >> 16) {
    case GROUP_A:
        switch (state & 0xFFFF) {
            case BLOCK_1: ...
            case BLOCK_2: ...
        }
    case GROUP_B:
        switch (state & 0xFFFF) {
            case BLOCK_3: ...
            case BLOCK_4: ...
        }
}
```

### 变体 2: 加密状态变量

```c
// 状态变量经过加密，增加静态分析难度
state = (state ^ KEY1) + KEY2;
state = ROL(state, KEY3);
// 在 dispatcher 中解密后比较
decrypted = ROR(state, KEY3) - KEY2;
decrypted ^= KEY1;
switch (decrypted) { ... }
```

### 变体 3: 计算跳转

```asm
; 不使用 switch，而是通过计算得到目标地址
mov     eax, [ebp-4]            ; state
imul    eax, STRIDE
add     eax, JUMP_TABLE_BASE
jmp     eax                     ; 计算跳转
```

### 变体 4: 间接跳转 + 函数指针

```c
// 使用函数指针数组实现分发
typedef void (*handler_t)(context_t*);
handler_t handlers[] = {block_A, block_B, block_C, ...};

while (state != EXIT_STATE) {
    int index = decrypt_state(state);
    handlers[index](&ctx);
    state = ctx.next_state;
}
```

## 增强版平坦化

### OLLVM Fork 中的增强

#### 1. 多 Dispatcher

```
不使用单一 dispatcher，而是多个 dispatcher 交替使用:

dispatcher_1 → block_A → dispatcher_2 → block_B → dispatcher_1 → block_C
```

#### 2. 状态变量复杂化

```c
// 使用多个变量组合作为状态
state1 = f(state1, state2);
state2 = g(state1, state2);

// 分发条件: state1 + state2 == TARGET
if (state1 + state2 == HASH_A) goto block_A;
if (state1 * state2 == HASH_B) goto block_B;
```

#### 3. 混合 MBA (Mixed Boolean-Arithmetic) 状态

```c
// MBA 混淆的状态转换
next_state = (state & 0xFF00FF00) | ((~state) & 0x00FF00FF);
next_state = next_state ^ ((state << 13) | (state >> 19));
next_state += 0xDEADBEEF;
```

## 解平坦化核心算法

### 算法 1: 基于符号执行的状态恢复

```python
import angr
import claripy

class CFFDeflattener:
    def __init__(self, proj, func_addr):
        self.proj = proj
        self.func_addr = func_addr
        self.cfg = proj.analyses.CFGFast(
            regions=[(func_addr, func_addr + 0x10000)]
        )
    
    def identify_components(self):
        """识别平坦化组件"""
        func = self.cfg.functions[self.func_addr]
        
        # 1. 找到 dispatcher (入度最高的基本块)
        max_in_degree = 0
        for node in func.graph.nodes():
            in_degree = func.graph.in_degree(node)
            if in_degree > max_in_degree:
                max_in_degree = in_degree
                self.dispatcher = node
        
        # 2. 找到 prologue (函数入口到 dispatcher 之间)
        self.prologue = func.graph.nodes()[0]
        
        # 3. 找到所有 case blocks (dispatcher 的后继)
        self.case_blocks = list(func.graph.successors(self.dispatcher))
        
        # 4. 识别状态变量
        self.state_var = self.find_state_variable()
    
    def find_state_variable(self):
        """识别控制分发的状态变量"""
        # 在 dispatcher 中查找 cmp/switch 使用的变量
        # 通常是栈上的局部变量
        block = self.proj.factory.block(self.dispatcher.addr)
        for stmt in block.vex.statements:
            # 查找 comparison 操作
            if hasattr(stmt, 'data') and hasattr(stmt.data, 'op'):
                if 'Cmp' in stmt.data.op:
                    return self.extract_compared_variable(stmt)
        return None
    
    def recover_transitions(self):
        """恢复基本块之间的真实转换关系"""
        transitions = {}
        
        for block in self.case_blocks:
            # 对每个 case block 进行符号执行
            state = self.proj.factory.blank_state(addr=block.addr)
            
            # 符号化状态变量
            state_sym = claripy.BVS("state", 32)
            state.memory.store(self.state_var_addr, state_sym)
            
            # 执行到 dispatcher
            simgr = self.proj.factory.simulation_manager(state)
            simgr.step(until=lambda sm: all(
                s.addr == self.dispatcher.addr for s in sm.active
            ))
            
            # 提取状态变量的新值
            for s in simgr.active:
                new_state = s.memory.load(self.state_var_addr, 4)
                # 求解可能的目标状态
                for target_state in self.known_states:
                    if s.solver.satisfiable(
                        extra_constraints=[new_state == target_state]
                    ):
                        target_block = self.state_to_block[target_state]
                        transitions.setdefault(block.addr, []).append(
                            target_block.addr
                        )
            
        return transitions
    
    def reconstruct_cfg(self, transitions):
        """重建原始 CFG"""
        import networkx as nx
        
        original_cfg = nx.DiGraph()
        
        for src, dests in transitions.items():
            for dst in dests:
                original_cfg.add_edge(src, dst)
        
        return original_cfg
```

### 算法 2: 基于数据流分析的解平坦化

```python
class DataFlowDeflattener:
    def __init__(self, func_ir):
        self.func_ir = func_ir
    
    def analyze(self):
        """基于数据流的解平坦化"""
        # 1. 定位状态变量的定义-使用链
        state_var_def_use = self.build_def_use_chain(self.state_var)
        
        # 2. 对每个基本块，追踪状态变量的赋值
        state_assignments = {}
        for block in self.case_blocks:
            assignments = self.find_state_assignments(block, state_var_def_use)
            state_assignments[block] = assignments
        
        # 3. 求解状态常量
        transitions = {}
        for block, assignments in state_assignments.items():
            for assign in assignments:
                if self.is_constant(assign.value):
                    target = self.state_to_block(assign.value)
                    transitions.setdefault(block, []).append(target)
                elif self.is_conditional(assign):
                    true_target = self.state_to_block(assign.true_value)
                    false_target = self.state_to_block(assign.false_value)
                    transitions.setdefault(block, []).append(
                        ('conditional', assign.condition, true_target, false_target)
                    )
        
        return transitions
```

### 算法 3: 基于执行 Trace 的恢复

```python
class TraceBasedDeflattener:
    def __init__(self, binary, func_addr):
        self.binary = binary
        self.func_addr = func_addr
    
    def collect_traces(self, inputs):
        """收集多组输入的执行 trace"""
        all_traces = []
        for inp in inputs:
            trace = self.execute_and_trace(inp)
            block_sequence = self.extract_block_sequence(trace)
            all_traces.append(block_sequence)
        return all_traces
    
    def infer_cfg(self, traces):
        """从多条 trace 推断原始 CFG"""
        edges = set()
        
        for trace in traces:
            # 过滤掉 dispatcher 和 prologue
            real_blocks = [b for b in trace 
                          if b != self.dispatcher and b != self.prologue]
            
            # 相邻的 real blocks 之间存在边
            for i in range(len(real_blocks) - 1):
                edges.add((real_blocks[i], real_blocks[i+1]))
        
        return edges
```

## 工具层面的解平坦化

### IDA Plugin: D-810

```
D-810 (IDA 解混淆插件):
- 基于 Hex-Rays microcode API
- 自动识别并解除控制流平坦化
- 支持多种 OLLVM 变体
- 工作在 IDA 的反编译层面

使用方法:
1. 安装 D-810 插件
2. 在 IDA 中打开目标二进制
3. 定位被混淆的函数
4. Edit → Plugins → D-810
5. 选择 "Unflattening" 规则
6. 应用并重新反编译
```

### Binary Ninja: Deobfuscation Plugin

```python
# BinaryNinja 解平坦化伪代码
from binaryninja import *

class Deflattener(BackgroundTaskThread):
    def run(self):
        func = self.bv.get_function_at(self.target)
        mlil = func.medium_level_il
        
        # 1. 识别 dispatcher 和 state variable
        dispatcher = self.find_dispatcher(mlil)
        state_var = self.find_state_var(mlil, dispatcher)
        
        # 2. 收集所有状态常量
        states = self.collect_states(mlil, state_var)
        
        # 3. 计算块间转换
        transitions = self.compute_transitions(mlil, state_var, states)
        
        # 4. Patch binary: 替换 jmp dispatcher 为直接跳转
        for src, dst in transitions.items():
            self.patch_branch(src, dst)
```
