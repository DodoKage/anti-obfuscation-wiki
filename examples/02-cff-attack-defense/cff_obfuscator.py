#!/usr/bin/env python3
"""
[攻击方] OLLVM 控制流平坦化模拟器
将 Python AST 级别的函数自动变换为控制流平坦化形式。
模拟 OLLVM 的 -fla pass 对代码的变换效果。
"""

import random
import hashlib


class BasicBlock:
    def __init__(self, block_id, code, successors=None, condition=None):
        self.id = block_id
        self.code = code
        self.successors = successors or []
        self.condition = condition
        self.state_hash = random.randint(0x10000000, 0x7FFFFFFF)

    def __repr__(self):
        return f"BB_{self.id}(state=0x{self.state_hash:08X})"


class CFFObfuscator:
    """控制流平坦化混淆器"""

    def __init__(self, encrypt_state=False):
        self.blocks = []
        self.encrypt_state = encrypt_state
        self.state_key = random.randint(1, 0xFFFF) if encrypt_state else 0

    def add_block(self, block):
        self.blocks.append(block)

    def flatten(self):
        """将基本块序列变换为平坦化的 switch-case 结构"""
        if not self.blocks:
            return ""

        lines = []
        lines.append("def flattened_function(args):")
        lines.append(f"    # [OLLVM CFF] Dispatcher-based control flow")
        lines.append(f"    # Original: {len(self.blocks)} basic blocks")
        lines.append(f"    state = 0x{self.blocks[0].state_hash:08X}")

        if self.encrypt_state:
            lines.append(f"    _key = 0x{self.state_key:04X}")

        lines.append(f"    while True:")

        if self.encrypt_state:
            lines.append(f"        _dec = state ^ _key")
            cmp_var = "_dec"
        else:
            cmp_var = "state"

        for i, block in enumerate(self.blocks):
            prefix = "if" if i == 0 else "elif"
            cmp_val = block.state_hash
            if self.encrypt_state:
                cmp_val = block.state_hash ^ self.state_key

            lines.append(f"        {prefix} {cmp_var} == 0x{cmp_val:08X}:  # Block {block.id}")

            for code_line in block.code:
                lines.append(f"            {code_line}")

            if block.condition:
                true_target = self._find_block(block.successors[0])
                false_target = self._find_block(block.successors[1])
                lines.append(f"            if {block.condition}:")
                lines.append(f"                state = 0x{true_target.state_hash:08X}")
                lines.append(f"            else:")
                lines.append(f"                state = 0x{false_target.state_hash:08X}")
            elif block.successors:
                target = self._find_block(block.successors[0])
                lines.append(f"            state = 0x{target.state_hash:08X}")
            else:
                lines.append(f"            return result")

        lines.append(f"        else:")
        lines.append(f"            break  # unreachable")

        return "\n".join(lines)

    def _find_block(self, block_id):
        for b in self.blocks:
            if b.id == block_id:
                return b
        raise ValueError(f"Block {block_id} not found")

    def get_state_map(self):
        return {b.id: b.state_hash for b in self.blocks}

    def get_transition_map(self):
        transitions = {}
        for b in self.blocks:
            if b.condition:
                transitions[b.id] = {
                    'type': 'conditional',
                    'condition': b.condition,
                    'true': b.successors[0],
                    'false': b.successors[1],
                }
            elif b.successors:
                transitions[b.id] = {
                    'type': 'unconditional',
                    'target': b.successors[0],
                }
            else:
                transitions[b.id] = {'type': 'return'}
        return transitions


def demo_simple_if():
    """
    原始代码:
    def check(x):
        if x > 10:
            result = x * 2
        else:
            result = x + 5
        return result
    """
    print("=" * 60)
    print("案例 1: 简单 if-else 的平坦化")
    print("=" * 60)

    print("\n[原始代码]")
    print("""
def check(x):
    if x > 10:
        result = x * 2
    else:
        result = x + 5
    return result
""")

    obf = CFFObfuscator()

    obf.add_block(BasicBlock(
        'entry', ['x = args[0]'],
        successors=['then', 'else_'], condition='x > 10'
    ))
    obf.add_block(BasicBlock(
        'then', ['result = x * 2'],
        successors=['exit']
    ))
    obf.add_block(BasicBlock(
        'else_', ['result = x + 5'],
        successors=['exit']
    ))
    obf.add_block(BasicBlock(
        'exit', ['pass'],
        successors=[]
    ))

    flattened = obf.flatten()
    print("[平坦化后]")
    print(flattened)

    print(f"\n[状态映射 (密钥)]")
    for bid, state in obf.get_state_map().items():
        print(f"  Block {bid:8s} → state 0x{state:08X}")

    print(f"\n[转换关系]")
    for bid, trans in obf.get_transition_map().items():
        if trans['type'] == 'conditional':
            print(f"  {bid} → if {trans['condition']}: {trans['true']} else: {trans['false']}")
        elif trans['type'] == 'unconditional':
            print(f"  {bid} → {trans['target']}")
        else:
            print(f"  {bid} → return")

    return obf


def demo_loop():
    """
    原始代码:
    def sum_to_n(n):
        total = 0
        i = 0
        while i < n:
            total += i
            i += 1
        return total
    """
    print("\n" + "=" * 60)
    print("案例 2: 循环的平坦化")
    print("=" * 60)

    print("\n[原始代码]")
    print("""
def sum_to_n(n):
    total = 0
    i = 0
    while i < n:
        total += i
        i += 1
    return total
""")

    obf = CFFObfuscator(encrypt_state=True)

    obf.add_block(BasicBlock(
        'init', ['n = args[0]', 'total = 0', 'i = 0'],
        successors=['loop_cond']
    ))
    obf.add_block(BasicBlock(
        'loop_cond', ['pass'],
        successors=['loop_body', 'exit'], condition='i < n'
    ))
    obf.add_block(BasicBlock(
        'loop_body', ['total += i', 'i += 1'],
        successors=['loop_cond']
    ))
    obf.add_block(BasicBlock(
        'exit', ['result = total'],
        successors=[]
    ))

    flattened = obf.flatten()
    print("[平坦化后 (带状态加密)]")
    print(flattened)

    return obf


def demo_nested():
    """
    原始代码:
    def classify(x, y):
        if x > 0:
            if y > 0:
                result = "Q1"
            else:
                result = "Q4"
        else:
            if y > 0:
                result = "Q2"
            else:
                result = "Q3"
        return result
    """
    print("\n" + "=" * 60)
    print("案例 3: 嵌套条件的平坦化")
    print("=" * 60)

    print("\n[原始代码]")
    print("""
def classify(x, y):
    if x > 0:
        if y > 0:   result = "Q1"
        else:        result = "Q4"
    else:
        if y > 0:   result = "Q2"
        else:        result = "Q3"
    return result
""")

    obf = CFFObfuscator()

    obf.add_block(BasicBlock('entry', ['x, y = args[0], args[1]'],
                             successors=['x_pos', 'x_neg'], condition='x > 0'))
    obf.add_block(BasicBlock('x_pos', ['pass'],
                             successors=['q1', 'q4'], condition='y > 0'))
    obf.add_block(BasicBlock('x_neg', ['pass'],
                             successors=['q2', 'q3'], condition='y > 0'))
    obf.add_block(BasicBlock('q1', ['result = "Q1"'], successors=['exit']))
    obf.add_block(BasicBlock('q2', ['result = "Q2"'], successors=['exit']))
    obf.add_block(BasicBlock('q3', ['result = "Q3"'], successors=['exit']))
    obf.add_block(BasicBlock('q4', ['result = "Q4"'], successors=['exit']))
    obf.add_block(BasicBlock('exit', ['pass'], successors=[]))

    flattened = obf.flatten()
    print("[平坦化后]")
    print(flattened)

    return obf


if __name__ == '__main__':
    obf1 = demo_simple_if()
    obf2 = demo_loop()
    obf3 = demo_nested()
