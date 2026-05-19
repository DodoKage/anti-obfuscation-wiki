# 指令替换 (Instruction Substitution) 深度分析

## 替换规则全集

### 加法替换 (a + b)

```
规则 1: a + b = a - (-b)
规则 2: a + b = -(-a - b)
规则 3: a + b = (a ^ b) + 2*(a & b)
规则 4: a + b = (a | b) + (a & b)
规则 5: a + b = 2*(a | b) - (a ^ b)
规则 6: a + b = r + a + b - r        (r = random constant)
```

### 减法替换 (a - b)

```
规则 1: a - b = a + (-b)
规则 2: a - b = -(-a + b)
规则 3: a - b = (a ^ b) - 2*(~a & b)
规则 4: a - b = (a & ~b) - (~a & b)
规则 5: a - b = 2*(a & ~b) - (a ^ b)
规则 6: a - b = r + a - b - r        (r = random constant)
```

### 异或替换 (a ^ b)

```
规则 1: a ^ b = (~a & b) | (a & ~b)
规则 2: a ^ b = (a | b) & (~a | ~b)
规则 3: a ^ b = (a | b) & ~(a & b)
规则 4: a ^ b = (~a & b) | (a & ~b)  (展开形式)
规则 5: a ^ b = (a + b) - 2*(a & b)
规则 6: a ^ b = (a | b) - (a & b)
```

### 与运算替换 (a & b)

```
规则 1: a & b = (a | b) & ~(~a | ~b)  → 简化: ~(~a | ~b)
规则 2: a & b = ~(~a | ~b)
规则 3: a & b = (a + b) - (a | b)
规则 4: a & b = ((a ^ b) + (a | b)) / 2  (仅当无溢出)
规则 5: a & b = a + b - (a | b)
```

### 或运算替换 (a | b)

```
规则 1: a | b = (a & b) | (a ^ b)
规则 2: a | b = ~(~a & ~b)
规则 3: a | b = (a + b) - (a & b)
规则 4: a | b = a + b - (a & b)
```

### 取反替换 (NOT)

```
规则 1: ~a = -a - 1
规则 2: ~a = (a ^ -1)
规则 3: ~a = -1 - a
```

## MBA (Mixed Boolean-Arithmetic) 混淆

### 什么是 MBA

MBA 是一种更高级的指令替换技术，使用布尔运算和算术运算的混合表达式来替换简单运算。

```
线性 MBA:
e = c₁*(x & y) + c₂*(x | y) + c₃*(x ^ y) + c₄*(~x & y) + ... + c₀

其中 e 等价于某个简单表达式 f(x, y)

例: x + y = (x ^ y) + 2*(x & y)
    → MBA 展开: 1*(x ^ y) + 2*(x & y) + 0*(x | y) + 0*(~x & y) + ...
```

### MBA 混淆示例

```c
// 原始: a + b
// MBA 混淆后:
int obfuscated_add(int a, int b) {
    int r1 = a ^ b;
    int r2 = a & b;
    int r3 = ~a & b;
    int r4 = a | b;
    
    // 线性 MBA: result = 39*(a&b) + 1*(a|b) - 40*(~a&b) + 1*(a^b)
    // 等价于 a + b (对所有可能的 a, b 值)
    return 39 * r2 + 1 * r4 - 40 * r3 + 1 * r1;
}
```

### 多项式 MBA

```c
// 更复杂的多项式 MBA
// 原始: x ^ y
int obfuscated_xor(int x, int y) {
    return  2 * (x & y) * (~x | ~y) 
          + (x | y) * (~x & ~y) 
          - 3 * (x & ~y) * (~x & y) 
          + (x | y) - (x & y);
    // 数学上等价于 x ^ y
}
```

## MBA 简化算法

### 方法 1: 查找表 (Truth Table) 方法

```python
def simplify_mba_truth_table(expr, num_vars=2):
    """使用真值表穷举简化 MBA 表达式"""
    # 计算表达式在所有输入组合下的值
    truth_table = []
    for x in range(256):  # 8-bit 简化验证
        for y in range(256):
            result = eval_expr(expr, x, y) & 0xFF
            truth_table.append(result)
    
    # 与已知简单表达式的真值表比较
    known_exprs = {
        'x + y': lambda x, y: (x + y) & 0xFF,
        'x - y': lambda x, y: (x - y) & 0xFF,
        'x ^ y': lambda x, y: (x ^ y) & 0xFF,
        'x & y': lambda x, y: (x & y) & 0xFF,
        'x | y': lambda x, y: (x | y) & 0xFF,
        'x': lambda x, y: x,
        'y': lambda x, y: y,
        '~x': lambda x, y: (~x) & 0xFF,
        '~y': lambda x, y: (~y) & 0xFF,
        'x * y': lambda x, y: (x * y) & 0xFF,
    }
    
    for name, func in known_exprs.items():
        expected = []
        for x in range(256):
            for y in range(256):
                expected.append(func(x, y))
        
        if truth_table == expected:
            return name
    
    return None  # 无法简化
```

### 方法 2: 线性代数方法 (SSPAM/SiMBA)

```python
import numpy as np

def simplify_linear_mba(coefficients):
    """
    简化线性 MBA 表达式
    输入: coefficients = [c0, c1, c2, c3, c4, c5, c6, c7, c8]
    对应: c0 + c1*(x&y) + c2*(x|y) + c3*(x^y) + c4*(~x&y) + 
          c5*(x&~y) + c6*(~x&~y) + c7*(~x|y) + c8*(x|~y)
    """
    # 基向量的真值表 (2-bit 输入)
    # x: 0 0 1 1
    # y: 0 1 0 1
    basis_vectors = np.array([
        [1, 1, 1, 1],   # constant 1
        [0, 0, 0, 1],   # x & y
        [0, 1, 1, 1],   # x | y
        [0, 1, 1, 0],   # x ^ y
        [0, 1, 0, 0],   # ~x & y
        [0, 0, 1, 0],   # x & ~y
        [1, 0, 0, 0],   # ~x & ~y
        [1, 1, 0, 1],   # ~x | y
        [1, 0, 1, 1],   # x | ~y
    ])
    
    # 计算 MBA 表达式的真值表
    result_vector = np.zeros(4, dtype=int)
    for i, coeff in enumerate(coefficients):
        result_vector += coeff * basis_vectors[i]
    
    # 对结果取模 (n-bit)
    result_vector = result_vector % 256  # 8-bit
    
    # 匹配简单表达式
    simple_exprs = {
        (0, 1, 1, 0): 'x ^ y',
        (0, 0, 0, 1): 'x & y',
        (0, 1, 1, 1): 'x | y',
        (0, 1, 0, 1): 'x + y (mod 256)',
        # ...
    }
    
    key = tuple(result_vector)
    return simple_exprs.get(key, f"unknown: {key}")
```

### 方法 3: 基于 Rewriting Rules 的简化

```python
class MBARewriter:
    """基于重写规则的 MBA 简化"""
    
    RULES = [
        # (pattern, replacement)
        # a ^ b 的等价形式
        ('(~{a} & {b}) | ({a} & ~{b})', '{a} ^ {b}'),
        ('({a} | {b}) & (~{a} | ~{b})', '{a} ^ {b}'),
        ('({a} | {b}) & ~({a} & {b})', '{a} ^ {b}'),
        
        # a & b 的等价形式
        ('~(~{a} | ~{b})', '{a} & {b}'),
        ('({a} + {b}) - ({a} | {b})', '{a} & {b}'),
        
        # a | b 的等价形式
        ('~(~{a} & ~{b})', '{a} | {b}'),
        ('({a} & {b}) | ({a} ^ {b})', '{a} | {b}'),
        ('({a} + {b}) - ({a} & {b})', '{a} | {b}'),
        
        # a + b 的等价形式
        ('({a} ^ {b}) + 2 * ({a} & {b})', '{a} + {b}'),
        ('({a} | {b}) + ({a} & {b})', '{a} + {b}'),
        
        # 恒等式消除
        ('{a} ^ {a}', '0'),
        ('{a} | {a}', '{a}'),
        ('{a} & {a}', '{a}'),
        ('{a} - {a}', '0'),
        ('~(~{a})', '{a}'),
        ('{a} ^ 0', '{a}'),
        ('{a} | 0', '{a}'),
        ('{a} & 0', '0'),
        ('{a} + 0', '{a}'),
    ]
    
    def simplify(self, expr, max_iterations=100):
        for _ in range(max_iterations):
            changed = False
            for pattern, replacement in self.RULES:
                new_expr, did_change = self.apply_rule(expr, pattern, replacement)
                if did_change:
                    expr = new_expr
                    changed = True
            
            if not changed:
                break
        
        return expr
```

## 汇编层面的指令替换识别

### 常见模式

```asm
; 原始: add eax, ebx
; 替换后 (规则3): (a ^ b) + 2*(a & b)
mov     ecx, eax
xor     ecx, ebx         ; a ^ b
mov     edx, eax
and     edx, ebx          ; a & b
shl     edx, 1             ; 2 * (a & b)
add     ecx, edx           ; (a ^ b) + 2*(a & b)
mov     eax, ecx           ; result = a + b

; 原始: xor eax, ebx
; 替换后 (规则1): (~a & b) | (a & ~b)
mov     ecx, eax
not     ecx                ; ~a
and     ecx, ebx           ; ~a & b
mov     edx, ebx
not     edx                ; ~b
and     edx, eax           ; a & ~b
or      ecx, edx           ; (~a & b) | (a & ~b)
mov     eax, ecx           ; result = a ^ b
```

### 自动识别脚本

```python
# IDA Python: 识别指令替换模式
def find_substitution_patterns(func_addr):
    """查找指令替换模式"""
    func = idaapi.get_func(func_addr)
    results = []
    
    for block in idaapi.FlowChart(func):
        insns = get_block_instructions(block)
        
        # 滑动窗口匹配
        for i in range(len(insns)):
            # 检查 ADD 替换: xor + and + shl + add
            if i + 5 < len(insns):
                pattern = [get_mnem(insns[j]) for j in range(i, i+6)]
                if matches_add_substitute(pattern, insns[i:i+6]):
                    results.append({
                        'type': 'add_substitute',
                        'start': insns[i],
                        'end': insns[i+5],
                        'simplified': 'add',
                    })
            
            # 检查 XOR 替换: not + and + not + and + or
            if i + 6 < len(insns):
                if matches_xor_substitute(insns[i:i+7]):
                    results.append({
                        'type': 'xor_substitute',
                        'start': insns[i],
                        'end': insns[i+6],
                        'simplified': 'xor',
                    })
    
    return results
```

## 多轮替换与嵌套

### 嵌套替换示例

```
Level 0: a + b
Level 1: (a ^ b) + 2*(a & b)                       [替换 +]
Level 2: ((~a&b)|(a&~b)) + 2*(~(~a|~b))            [替换 ^ 和 &]
Level 3: ...更深层展开...

每一轮替换都使表达式复杂度指数增长
```

### 对抗策略

```python
def iterative_simplification(expr, max_depth=10):
    """迭代简化多层嵌套的指令替换"""
    rewriter = MBARewriter()
    
    for depth in range(max_depth):
        simplified = rewriter.simplify(expr)
        
        if simplified == expr:
            break  # 无法进一步简化
        
        expr = simplified
        print(f"Depth {depth}: {expr}")
    
    return expr
```
