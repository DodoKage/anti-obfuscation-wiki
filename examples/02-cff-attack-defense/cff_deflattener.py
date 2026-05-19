#!/usr/bin/env python3
"""
[防御方] OLLVM 控制流解平坦化器
从平坦化的代码中恢复原始控制流图 (CFG)。

策略:
1. 识别 dispatcher 和 state 变量
2. 收集所有 state 常量
3. 分析每个 case block 的 state 转换
4. 重建原始 CFG
5. 生成恢复后的代码
"""

import re
import json
from collections import defaultdict


class CFGNode:
    def __init__(self, block_id, code, state_value=None):
        self.id = block_id
        self.code = code
        self.state = state_value
        self.true_successor = None
        self.false_successor = None
        self.unconditional_successor = None
        self.condition = None
        self.is_return = False

    def __repr__(self):
        return f"Node({self.id}, state=0x{self.state:08X})" if self.state else f"Node({self.id})"


class CFFDeflattener:
    """控制流解平坦化器"""

    def __init__(self):
        self.state_map = {}    # state_value → block
        self.transitions = {}  # block_id → successors
        self.blocks = {}       # block_id → CFGNode

    def analyze(self, flattened_code):
        """分析平坦化代码，提取 state 映射和转换关系"""
        print("[*] Step 1: 识别 dispatcher 和 state 变量")

        # 找初始 state
        init_match = re.search(r'state\s*=\s*(0x[0-9A-Fa-f]+)', flattened_code)
        if init_match:
            init_state = int(init_match.group(1), 16)
            print(f"    初始 state: 0x{init_state:08X}")

        # 找加密 key (如果有)
        key_match = re.search(r'_key\s*=\s*(0x[0-9A-Fa-f]+)', flattened_code)
        encrypt_key = int(key_match.group(1), 16) if key_match else 0
        if encrypt_key:
            print(f"    加密 key: 0x{encrypt_key:04X}")

        # 检测比较变量
        dec_match = re.search(r'_dec\s*=\s*state\s*\^\s*_key', flattened_code)
        uses_encryption = dec_match is not None
        if uses_encryption:
            print(f"    检测到状态加密 (state ^ key)")

        print("\n[*] Step 2: 提取所有 case blocks")

        # 解析 if/elif 链
        block_pattern = re.compile(
            r'(?:if|elif)\s+\w+\s*==\s*(0x[0-9A-Fa-f]+):\s*#\s*Block\s+(\w+)',
            re.MULTILINE
        )

        blocks_found = []
        for match in block_pattern.finditer(flattened_code):
            cmp_val = int(match.group(1), 16)
            block_id = match.group(2)

            if uses_encryption:
                actual_state = cmp_val ^ encrypt_key
            else:
                actual_state = cmp_val

            blocks_found.append((block_id, actual_state, match.start()))
            self.state_map[actual_state] = block_id
            print(f"    Block {block_id:10s} → state 0x{actual_state:08X}")

        print(f"\n[*] Step 3: 分析 state 转换关系")

        # 对每个 block，找它设置的下一个 state
        lines = flattened_code.split('\n')

        for i, (block_id, state, _) in enumerate(blocks_found):
            # 找这个 block 到下一个 block 之间的代码
            next_block_start = blocks_found[i + 1][2] if i + 1 < len(blocks_found) else len(flattened_code)
            block_code = flattened_code[_:next_block_start]

            # 查找 state 赋值
            state_assigns = re.findall(r'state\s*=\s*(0x[0-9A-Fa-f]+)', block_code)

            # 查找条件
            cond_match = re.search(r'if\s+(.+?):\s*\n\s+state\s*=', block_code)

            # 检查是否是 return
            if 'return' in block_code:
                self.transitions[block_id] = {'type': 'return'}
                node = CFGNode(block_id, self._extract_code(block_code), state)
                node.is_return = True
                self.blocks[block_id] = node
                print(f"    {block_id:10s} → RETURN")
                continue

            node = CFGNode(block_id, self._extract_code(block_code), state)

            if cond_match and len(state_assigns) >= 2:
                condition = cond_match.group(1).strip()
                true_state = int(state_assigns[0], 16)
                false_state = int(state_assigns[1], 16)

                true_block = self.state_map.get(true_state, f'unknown_0x{true_state:08X}')
                false_block = self.state_map.get(false_state, f'unknown_0x{false_state:08X}')

                self.transitions[block_id] = {
                    'type': 'conditional',
                    'condition': condition,
                    'true': true_block,
                    'false': false_block,
                }
                node.condition = condition
                node.true_successor = true_block
                node.false_successor = false_block
                print(f"    {block_id:10s} → if {condition}: {true_block} else: {false_block}")

            elif state_assigns:
                target_state = int(state_assigns[0], 16)
                target_block = self.state_map.get(target_state, f'unknown_0x{target_state:08X}')

                self.transitions[block_id] = {
                    'type': 'unconditional',
                    'target': target_block,
                }
                node.unconditional_successor = target_block
                print(f"    {block_id:10s} → {target_block}")

            self.blocks[block_id] = node

    def _extract_code(self, block_code):
        """从 block 代码中提取有效代码 (去掉 state 赋值和 dispatcher 相关)"""
        lines = []
        skip_until_state = False
        for line in block_code.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue
            if 'state =' in stripped:
                continue
            if stripped.startswith(('if ', 'elif ')):
                if '==' in stripped and ('0x' in stripped or '_dec' in stripped):
                    continue
                # 条件分支属于 transition 逻辑，不是真实代码
                if any(f'state' in l for l in block_code.split('\n') if stripped.split(':')[0] in l):
                    continue
            if stripped in ('pass', 'else:', 'break', 'break  # unreachable'):
                continue
            if 'break' in stripped:
                continue
            if 'return' in stripped:
                lines.append(stripped)
                continue
            # 过滤掉 dispatcher 内部的条件 state 赋值
            if stripped.startswith('if ') and 'state' not in stripped:
                pass  # keep real conditions (but they are captured in node.condition)
            lines.append(stripped)
        return lines

    def reconstruct(self):
        """重建原始代码"""
        print(f"\n[*] Step 4: 重建控制流图 (CFG)")

        # 找入口 block
        entry_block = None
        for bid, node in self.blocks.items():
            entry_block = bid
            break

        print(f"    入口: {entry_block}")

        # DFS 重建
        visited = set()
        result = []
        self._reconstruct_dfs(entry_block, result, visited, indent=1)

        print(f"\n[*] Step 5: 生成恢复后的代码")
        code = "def recovered_function(args):\n"
        code += "\n".join(result)

        return code

    def _reconstruct_dfs(self, block_id, result, visited, indent):
        """深度优先重建代码"""
        if block_id in visited or block_id not in self.blocks:
            return
        visited.add(block_id)

        node = self.blocks[block_id]
        prefix = "    " * indent

        # 添加有效代码 (过滤掉条件表达式，因为 node.condition 会处理)
        for line in node.code:
            stripped = line.strip()
            if not stripped or stripped == 'pass':
                continue
            if node.condition and stripped.startswith('if ') and node.condition in stripped:
                continue
            result.append(f"{prefix}{stripped}")

        if node.is_return:
            return

        if node.condition:
            result.append(f"{prefix}if {node.condition}:")
            self._reconstruct_dfs(node.true_successor, result, visited.copy(), indent + 1)
            result.append(f"{prefix}else:")
            self._reconstruct_dfs(node.false_successor, result, visited.copy(), indent + 1)
        elif node.unconditional_successor:
            self._reconstruct_dfs(node.unconditional_successor, result, visited, indent)

    def verify(self, original_func, recovered_func, test_inputs):
        """验证恢复的代码是否与原始功能一致"""
        print(f"\n[*] Step 6: 差分验证")
        all_pass = True

        for inp in test_inputs:
            try:
                orig_result = original_func(inp)
                recov_result = recovered_func(inp)

                match = orig_result == recov_result
                status = "PASS" if match else "FAIL"
                if not match:
                    all_pass = False

                print(f"    Input={inp!r:20s} | Original={orig_result!r:10s} | "
                      f"Recovered={recov_result!r:10s} | {status}")
            except Exception as e:
                print(f"    Input={inp!r:20s} | ERROR: {e}")
                all_pass = False

        return all_pass


def demo():
    """完整对抗演示"""
    print("=" * 60)
    print("  CFF 对抗演示: 平坦化 → 解平坦化 → 验证")
    print("=" * 60)

    # === 攻击方: 平坦化 ===
    from cff_obfuscator import CFFObfuscator, BasicBlock

    print("\n[攻击方] 对 check(x) 函数进行控制流平坦化")
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

    flattened_code = obf.flatten()
    print("\n混淆后代码:")
    print(flattened_code)

    # === 防御方: 解平坦化 ===
    print("\n" + "=" * 60)
    print("[防御方] 解平坦化分析")
    print("=" * 60)

    deflat = CFFDeflattener()
    deflat.analyze(flattened_code)
    recovered_code = deflat.reconstruct()

    print("\n恢复后代码:")
    print(recovered_code)

    # === 验证 ===
    def original_check(args):
        x = args[0]
        if x > 10:
            return x * 2
        else:
            return x + 5

    # 编译并执行恢复的代码
    ns = {}
    exec(recovered_code, ns)
    recovered_func = ns.get('recovered_function')

    if recovered_func:
        test_inputs = [[5], [10], [15], [20], [0], [-5], [100]]
        deflat.verify(original_check, recovered_func, test_inputs)
    else:
        print("[!] 无法编译恢复后的代码")


if __name__ == '__main__':
    demo()
