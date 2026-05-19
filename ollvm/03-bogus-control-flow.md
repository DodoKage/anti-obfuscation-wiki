# 虚假控制流 (Bogus Control Flow, BCF) 深度分析

## BCF 实现原理

### LLVM Pass 层面

```
BCF 变换流程:

1. 遍历函数中的每个基本块
2. 克隆该基本块 (产生垃圾副本)
3. 在原始块前插入不透明谓词
4. 不透明谓词的 true 分支指向原始块
5. false 分支指向垃圾克隆块
6. 垃圾块最终也跳转到原始块 (保证不影响执行)
7. 可多轮应用 (-bcf_loop=N)
```

### 不透明谓词 (Opaque Predicates)

不透明谓词是 BCF 的核心。它们是计算结果在编译时已知但难以被静态分析工具识别的条件表达式。

#### OLLVM 使用的经典不透明谓词

```c
// 永真谓词 (Always True)
// 1. 基于数论
(x * (x + 1)) % 2 == 0          // 连续整数之积必为偶数
(x * x + x) % 2 == 0            // 等价形式
(3 * x * x + x) % 2 == 0        // 变体

// 2. 基于二次型
x * x >= 0                       // 平方非负 (整数溢出可能破坏)
(x | 1) != 0                     // 至少有一位为1

// 3. 基于恒等式
(x ^ y) == ((x | y) & ~(x & y)) // XOR 恒等式
((x & y) | (x ^ y)) == (x | y)  // 布尔恒等式

// 永假谓词 (Always False)
(x * (x + 1)) % 2 == 1          // 连续整数之积不可能为奇数
x * x < 0                        // 平方不为负 (整数范围内)
```

#### 增强版不透明谓词 (衍生项目)

```c
// MBA (Mixed Boolean-Arithmetic) 不透明谓词
((x ^ y) + 2 * (x & y)) == (x + y)     // 永真
((x | y) - (x & y)) == (x ^ y)          // 永真

// 基于哈希的不透明谓词
hash(global_var) % PRIME == EXPECTED     // 运行时计算

// 基于时间的不透明谓词 (反调试)
(clock() - start) < THRESHOLD           // 正常执行永真，调试时可能为假

// 基于环境的不透明谓词
getenv("DEBUG") == NULL                  // 特定环境下
```

## BCF 在汇编层面的表现

### 识别模式

```asm
; 典型的 BCF 模式 (x86)

; 1. 加载全局变量 (通常在 .bss 或 .data)
mov     eax, dword ptr [global_x]     ; x
mov     ecx, dword ptr [global_y]     ; y

; 2. 计算不透明谓词
; 例: (x * (x + 1)) % 2 == 0
lea     edx, [eax+1]                   ; x + 1
imul    edx, eax                       ; x * (x + 1)
and     edx, 1                         ; % 2
test    edx, edx                       ; == 0 ?
jnz     bogus_block                    ; 永不跳转 (但静态分析不确定)

; 3. 真实代码块
real_block:
    ; ... 原始代码 ...
    jmp     continue

; 4. 虚假代码块 (永不执行)
bogus_block:
    ; ... 垃圾代码 (通常是 real_block 的变异副本) ...
    jmp     real_block                  ; 最终跳回真实块

continue:
    ; ...
```

### 多轮 BCF

```
原始块 A:

Round 1: 
  OP1(永真) → A
  OP1(假)   → Bogus_A_1 → A

Round 2:
  OP2(永真) → [OP1 → A]
  OP2(假)   → Bogus_A_2 → [OP1 → A]

Round 3:
  OP3(永真) → [OP2 → OP1 → A]
  OP3(假)   → Bogus_A_3 → [OP2 → OP1 → A]

→ 最终: 3层嵌套的虚假控制流
```

## BCF 消除方法

### 方法 1: 不透明谓词识别与消除

#### 基于模式匹配的识别

```python
# IDA Python: 识别已知的不透明谓词模式
import idaapi
import idc

OPAQUE_PATTERNS = [
    # x*(x+1) % 2 == 0
    {
        'pattern': ['lea', 'imul', 'and', 'test', 'jnz'],
        'check': lambda insns: (
            'and' in str(insns[2]) and '1' in str(insns[2]) and
            'test' in str(insns[3])
        ),
        'result': 'always_true'
    },
    # x*x >= 0
    {
        'pattern': ['imul', 'test', 'js'],
        'check': lambda insns: True,
        'result': 'always_true'
    },
]

def identify_opaque_predicates(func_addr):
    """在函数中查找不透明谓词"""
    results = []
    func = idaapi.get_func(func_addr)
    
    for block in idaapi.FlowChart(func):
        insns = list(idautils.Heads(block.start_ea, block.end_ea))
        
        for pattern in OPAQUE_PATTERNS:
            if match_pattern(insns, pattern):
                branch_addr = insns[-1]  # 最后一条分支指令
                results.append({
                    'addr': branch_addr,
                    'type': pattern['result'],
                    'block': block.start_ea,
                })
    
    return results

def patch_opaque_predicates(predicates):
    """修补不透明谓词"""
    for pred in predicates:
        if pred['type'] == 'always_true':
            # jnz bogus → nop (因为条件永真，jnz永不跳转)
            nop_instruction(pred['addr'])
        elif pred['type'] == 'always_false':
            # jz bogus → jmp bogus 改为 nop
            nop_instruction(pred['addr'])
```

#### 基于抽象解释的识别

```python
# 使用 Z3 求解器验证谓词是否不透明
from z3 import *

def is_opaque_predicate(expr_ast):
    """使用 SMT 求解器判断表达式是否为不透明谓词"""
    solver = Solver()
    
    x = BitVec('x', 32)
    y = BitVec('y', 32)
    
    # 将 AST 转换为 Z3 表达式
    z3_expr = ast_to_z3(expr_ast, {'x': x, 'y': y})
    
    # 检查是否永真
    solver.push()
    solver.add(Not(z3_expr))  # 尝试找到使表达式为假的输入
    if solver.check() == unsat:
        solver.pop()
        return 'always_true'
    solver.pop()
    
    # 检查是否永假
    solver.push()
    solver.add(z3_expr)  # 尝试找到使表达式为真的输入
    if solver.check() == unsat:
        solver.pop()
        return 'always_false'
    solver.pop()
    
    return 'not_opaque'

# 示例验证
x = BitVec('x', 32)
expr = (x * (x + 1)) & 1 == 0  # x*(x+1) % 2 == 0

solver = Solver()
solver.add(Not(expr))
print(solver.check())  # unsat → 永真不透明谓词
```

### 方法 2: 死代码消除

```python
def remove_dead_blocks(cfg):
    """消除不可达的虚假基本块"""
    reachable = set()
    
    # BFS 从入口开始，标记所有可达块
    queue = [cfg.entry]
    while queue:
        block = queue.pop(0)
        if block in reachable:
            continue
        reachable.add(block)
        
        for succ in cfg.successors(block):
            # 如果边由永假谓词守护，跳过
            edge_pred = cfg.get_edge_predicate(block, succ)
            if is_always_false(edge_pred):
                continue
            queue.append(succ)
    
    # 删除不可达块
    dead_blocks = set(cfg.blocks) - reachable
    for block in dead_blocks:
        cfg.remove_block(block)
    
    return cfg, len(dead_blocks)
```

### 方法 3: 基于 Hex-Rays Microcode 的消除

```python
# IDA Hex-Rays Microcode API
import ida_hexrays

class BCFCleaner(ida_hexrays.optinsn_t):
    """Hex-Rays microcode 优化插件，消除 BCF"""
    
    def func(self, blk, ins, optflags):
        # 在 microcode 层面检测不透明谓词
        if ins.opcode == ida_hexrays.m_jcnd:
            cond = ins.l  # 条件表达式
            
            if self.is_opaque(cond):
                # 将条件跳转替换为无条件跳转或 nop
                if self.evaluate(cond):
                    # 永真: 移除分支 (fall through)
                    ins.opcode = ida_hexrays.m_nop
                    return 1
                else:
                    # 永假: 替换为无条件跳转
                    ins.opcode = ida_hexrays.m_goto
                    return 1
        
        return 0
    
    def is_opaque(self, cond):
        """检测 microcode 中的不透明谓词"""
        # 使用模式匹配或 Z3 求解
        pass
```

## 高级 BCF 对抗

### 对抗增强版不透明谓词

```python
# 处理 MBA 不透明谓词
def simplify_mba_predicate(expr):
    """
    简化 Mixed Boolean-Arithmetic 表达式
    使用 MBA 简化算法 (如 SSPAM/SiMBA)
    """
    from mba_simplifier import MBASimplifier
    
    simplifier = MBASimplifier()
    simplified = simplifier.simplify(expr)
    
    # 简化后检查是否为常量
    if is_constant(simplified):
        return simplified.value
    
    return None
```

### 对抗动态不透明谓词

```python
# 对于基于运行时值的不透明谓词
# 需要结合动态分析
def analyze_dynamic_opaque(func_addr, num_runs=100):
    """多次执行，统计分支走向"""
    branch_stats = {}  # {branch_addr: {'taken': N, 'not_taken': M}}
    
    for _ in range(num_runs):
        trace = execute_with_random_input(func_addr)
        for branch in trace.branches:
            if branch.addr not in branch_stats:
                branch_stats[branch.addr] = {'taken': 0, 'not_taken': 0}
            
            if branch.taken:
                branch_stats[branch.addr]['taken'] += 1
            else:
                branch_stats[branch.addr]['not_taken'] += 1
    
    # 找出单向分支 (可能是不透明谓词)
    opaque_candidates = []
    for addr, stats in branch_stats.items():
        total = stats['taken'] + stats['not_taken']
        if stats['taken'] == total or stats['not_taken'] == total:
            opaque_candidates.append(addr)
    
    return opaque_candidates
```

## 不透明谓词数据库

### 常见不透明谓词及其 Z3 证明

```python
from z3 import *

x, y = BitVecs('x y', 32)

opaque_predicates = {
    # 永真
    "x*(x+1) % 2 == 0": (x * (x + 1)) & 1 == 0,
    "x*x + x is even": ((x * x + x) & 1) == 0,
    "x^2 >= 0 (signed)": x * x >= 0,  # 注意: 溢出可能破坏
    "(x|1) != 0": (x | 1) != 0,
    "7*y^2 - 1 != x^2": 7 * y * y - 1 != x * x,
    
    # 永假
    "x*(x+1) % 2 == 1": (x * (x + 1)) & 1 == 1,
    "x^2 < 0 (unsigned)": ULT(x * x, 0),
}

for name, pred in opaque_predicates.items():
    s = Solver()
    s.add(Not(pred))
    result = s.check()
    print(f"{name}: {'Always True' if result == unsat else 'Not always true'}")
```
