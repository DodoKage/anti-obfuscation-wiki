#!/usr/bin/env python3
"""
[防御方] Mini-VMP 去虚拟化器
从执行 trace 或直接从加密字节码还原原始语义。

三种去虚拟化策略:
1. 基于 Trace 的模式匹配 (最简单)
2. 基于符号执行的语义恢复 (最精确)
3. 基于字节码解密的静态分析 (无需执行)
"""

import struct
import json
import sys
from collections import defaultdict


class SymbolicValue:
    """符号值，追踪数据的来源和运算链"""

    def __init__(self, name=None, op=None, left=None, right=None, const=None):
        self.name = name
        self.op = op
        self.left = left
        self.right = right
        self.const = const

    def is_const(self):
        return self.const is not None and self.op is None

    def is_var(self):
        return self.name is not None and self.op is None

    def __repr__(self):
        if self.const is not None and self.op is None:
            return f"0x{self.const:X}"
        if self.name and self.op is None:
            return self.name
        if self.op == 'NOT':
            return f"~({self.left})"
        if self.op == 'NAND':
            return f"NAND({self.left}, {self.right})"
        if self.op:
            op_sym = {
                'ADD': '+', 'SUB': '-', 'MUL': '*',
                'XOR': '^', 'AND': '&', 'OR': '|',
                'SHL': '<<', 'SHR': '>>',
            }.get(self.op, self.op)
            return f"({self.left} {op_sym} {self.right})"
        return "?"


class NandReducer:
    """NAND 链化简器：将 NAND 组合还原为标准逻辑运算"""

    @staticmethod
    def reduce(expr):
        if not isinstance(expr, SymbolicValue):
            return expr

        if expr.op == 'NAND':
            a = NandReducer.reduce(expr.left)
            b = NandReducer.reduce(expr.right)

            a_repr = repr(a)
            b_repr = repr(b)

            # NAND(NAND(x,y), NAND(x,y)) = AND(x,y) — must check before generic NAND(x,x)
            if (a_repr == b_repr and
                isinstance(a, SymbolicValue) and a.op == 'NAND'):
                inner_a = NandReducer.reduce(a.left)
                inner_b = NandReducer.reduce(a.right)
                return SymbolicValue(op='AND', left=inner_a, right=inner_b)

            # NAND(x, x) = NOT(x)
            if a_repr == b_repr:
                return SymbolicValue(op='NOT', left=a)

            # NAND(NOT(x), NOT(y)) = OR(x, y)
            if (isinstance(a, SymbolicValue) and a.op == 'NOT' and
                isinstance(b, SymbolicValue) and b.op == 'NOT'):
                return SymbolicValue(op='OR', left=a.left, right=b.left)

            return SymbolicValue(op='NAND', left=a, right=b)

        if expr.op == 'NOT':
            inner = NandReducer.reduce(expr.left)
            # NOT(NOT(x)) = x
            if isinstance(inner, SymbolicValue) and inner.op == 'NOT':
                return inner.left
            return SymbolicValue(op='NOT', left=inner)

        if expr.op and expr.left:
            left = NandReducer.reduce(expr.left)
            right = NandReducer.reduce(expr.right) if expr.right else None
            return SymbolicValue(op=expr.op, left=left, right=right, name=expr.name)

        return expr


class TraceDevirtualizer:
    """方法 1: 基于执行 Trace 的去虚拟化"""

    PATTERNS = [
        # (handler_sequence, generator)
        (['PUSH_REG', 'PUSH_REG', 'ADD', 'POP_REG'],
         lambda ops: f"R{ops[3]['reg']} = R{ops[0]['reg']} + R{ops[1]['reg']}"),

        (['PUSH_REG', 'PUSH_IMM', 'ADD', 'POP_REG'],
         lambda ops: f"R{ops[3]['reg']} = R{ops[0]['reg']} + {ops[1]['value']:#x}"),

        (['PUSH_REG', 'PUSH_REG', 'SUB', 'POP_REG'],
         lambda ops: f"R{ops[3]['reg']} = R{ops[0]['reg']} - R{ops[1]['reg']}"),

        (['PUSH_REG', 'PUSH_IMM', 'SUB', 'POP_REG'],
         lambda ops: f"R{ops[3]['reg']} = R{ops[0]['reg']} - {ops[1]['value']:#x}"),

        (['PUSH_REG', 'PUSH_REG', 'XOR', 'POP_REG'],
         lambda ops: f"R{ops[3]['reg']} = R{ops[0]['reg']} ^ R{ops[1]['reg']}"),

        (['PUSH_REG', 'PUSH_IMM', 'XOR', 'POP_REG'],
         lambda ops: f"R{ops[3]['reg']} = R{ops[0]['reg']} ^ {ops[1]['value']:#x}"),

        (['PUSH_REG', 'PUSH_REG', 'MUL', 'POP_REG'],
         lambda ops: f"R{ops[3]['reg']} = R{ops[0]['reg']} * R{ops[1]['reg']}"),

        (['PUSH_REG', 'PUSH_IMM', 'MUL', 'POP_REG'],
         lambda ops: f"R{ops[3]['reg']} = R{ops[0]['reg']} * {ops[1]['value']:#x}"),

        (['PUSH_REG', 'PUSH_REG', 'AND', 'POP_REG'],
         lambda ops: f"R{ops[3]['reg']} = R{ops[0]['reg']} & R{ops[1]['reg']}"),

        (['PUSH_REG', 'PUSH_IMM', 'SHR', 'POP_REG'],
         lambda ops: f"R{ops[3]['reg']} = R{ops[0]['reg']} >> {ops[1]['value']}"),

        (['PUSH_REG', 'PUSH_IMM', 'SHL', 'POP_REG'],
         lambda ops: f"R{ops[3]['reg']} = R{ops[0]['reg']} << {ops[1]['value']}"),
    ]

    def devirtualize(self, trace):
        """从 trace 中匹配模式，还原指令"""
        result = []
        i = 0

        while i < len(trace):
            matched = False

            for length in range(6, 1, -1):
                if i + length > len(trace):
                    continue

                window = trace[i:i+length]
                handler_seq = [e['handler'] for e in window]

                for pattern, gen in self.PATTERNS:
                    if handler_seq == pattern:
                        x86_inst = gen(window)
                        result.append(x86_inst)
                        i += length
                        matched = True
                        break

                if matched:
                    break

            if not matched:
                entry = trace[i]
                if entry['handler'] == 'HALT':
                    result.append('RET')
                elif entry['handler'] in ('JMP', 'JZ', 'JNZ'):
                    taken = entry.get('taken', '')
                    result.append(f"{entry['handler']} → offset {entry.get('target', '?')}"
                                 f" {'(TAKEN)' if taken else ''}")
                else:
                    result.append(f"; unmatched: {entry['handler']}")
                i += 1

        return result


class SymbolicDevirtualizer:
    """方法 2: 基于符号执行的去虚拟化"""

    def __init__(self):
        self.sym_regs = {}
        self.sym_stack = []

    def devirtualize(self, trace, num_regs=4):
        for i in range(num_regs):
            self.sym_regs[i] = SymbolicValue(name=f"R{i}")

        for entry in trace:
            handler = entry['handler']
            self._dispatch(handler, entry)

        return self.sym_regs

    def _dispatch(self, handler, entry):
        dispatch = {
            'PUSH_REG': self._push_reg,
            'PUSH_IMM': self._push_imm,
            'POP_REG': self._pop_reg,
            'ADD': lambda e: self._binop('ADD', e),
            'SUB': lambda e: self._binop('SUB', e),
            'MUL': lambda e: self._binop('MUL', e),
            'XOR': lambda e: self._binop('XOR', e),
            'AND': lambda e: self._binop('AND', e),
            'OR': lambda e: self._binop('OR', e),
            'NAND': lambda e: self._binop('NAND', e),
            'SHL': lambda e: self._binop('SHL', e),
            'SHR': lambda e: self._binop('SHR', e),
            'NOT': self._not,
            'HALT': lambda e: None,
            'CMP': self._cmp,
            'JMP': lambda e: None,
            'JZ': lambda e: None,
            'JNZ': lambda e: None,
        }

        fn = dispatch.get(handler)
        if fn:
            fn(entry)

    def _push_reg(self, entry):
        reg = entry['reg']
        self.sym_stack.append(self.sym_regs[reg])

    def _push_imm(self, entry):
        val = entry['value']
        self.sym_stack.append(SymbolicValue(const=val))

    def _pop_reg(self, entry):
        reg = entry['reg']
        self.sym_regs[reg] = self.sym_stack.pop()

    def _binop(self, op, entry):
        b = self.sym_stack.pop()
        a = self.sym_stack.pop()
        self.sym_stack.append(SymbolicValue(op=op, left=a, right=b))

    def _not(self, entry):
        a = self.sym_stack.pop()
        self.sym_stack.append(SymbolicValue(op='NOT', left=a))

    def _cmp(self, entry):
        b = self.sym_stack.pop()
        a = self.sym_stack.pop()
        self.sym_stack.append(a)  # CMP pushes a back


class StaticDevirtualizer:
    """方法 3: 静态字节码分析 (不需要执行 trace)"""

    def __init__(self, bytecode, encrypt_key, reverse_map=None):
        self.bytecode = bytecode
        self.key = encrypt_key
        self.reverse_map = {int(k): v for k, v in reverse_map.items()} if reverse_map else {}
        self.disassembly = []

    def _read_byte(self, offset):
        raw = self.bytecode[offset] ^ self.key
        return self.reverse_map.get(raw, raw)

    def _read_dword(self, offset):
        raw = bytes(b ^ self.key for b in self.bytecode[offset:offset+4])
        return struct.unpack('<I', raw)[0]

    def disassemble(self):
        """静态反汇编字节码"""
        OPCODE_NAMES = {
            0x01: 'PUSH_REG', 0x02: 'PUSH_IMM', 0x03: 'POP_REG',
            0x10: 'ADD', 0x11: 'SUB', 0x12: 'MUL',
            0x13: 'XOR', 0x14: 'AND', 0x15: 'OR',
            0x16: 'NOT', 0x17: 'NAND',
            0x18: 'SHL', 0x19: 'SHR',
            0x20: 'CMP',
            0x30: 'JMP', 0x31: 'JZ', 0x32: 'JNZ',
            0xFF: 'HALT',
        }

        HAS_OPERAND = {0x01, 0x02, 0x03, 0x30, 0x31, 0x32}

        offset = 0
        while offset < len(self.bytecode):
            addr = offset
            opcode = self._read_byte(offset)
            offset += 1
            name = OPCODE_NAMES.get(opcode, f'UNK_{opcode:02X}')

            if opcode in HAS_OPERAND and offset + 4 <= len(self.bytecode):
                operand = self._read_dword(offset)
                offset += 4
                self.disassembly.append((addr, name, operand))
            else:
                self.disassembly.append((addr, name, None))

            if opcode == 0xFF:
                break

        return self.disassembly

    def print_disassembly(self):
        for addr, name, operand in self.disassembly:
            if operand is not None:
                if name in ('PUSH_REG', 'POP_REG'):
                    print(f"  {addr:04X}: {name:12s} R{operand}")
                elif name in ('JMP', 'JZ', 'JNZ'):
                    print(f"  {addr:04X}: {name:12s} → offset {operand:#x}")
                else:
                    print(f"  {addr:04X}: {name:12s} {operand:#010x}")
            else:
                print(f"  {addr:04X}: {name}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Mini-VMP Devirtualizer')
    parser.add_argument('--trace', help='Execution trace JSON file')
    parser.add_argument('--bytecode', help='Bytecode file for static analysis')
    parser.add_argument('--meta', help='Metadata file')
    parser.add_argument('--method', choices=['trace', 'symbolic', 'static', 'all'],
                       default='all', help='Devirtualization method')
    args = parser.parse_args()

    print("=" * 60)
    print("  Mini-VMP Devirtualizer — 去虚拟化器")
    print("=" * 60)

    # Static analysis
    if args.bytecode or (not args.trace):
        bc_file = args.bytecode
        meta_file = args.meta

        if not bc_file:
            print("[!] No bytecode or trace provided. Use --bytecode or --trace")
            sys.exit(1)

        if not meta_file:
            meta_file = bc_file.replace('.vbc', '.meta.json')

        with open(bc_file, 'rb') as f:
            bytecode = f.read()
        with open(meta_file, 'r') as f:
            metadata = json.load(f)

        if args.method in ('static', 'all'):
            print(f"\n{'─'*60}")
            print("[策略 3] 静态字节码反汇编 (无需执行)")
            print(f"{'─'*60}")
            print(f"[*] Key: 0x{metadata['encrypt_key']:02X}")
            print(f"[*] Bytecode: {len(bytecode)} bytes\n")

            static = StaticDevirtualizer(
                bytecode,
                metadata['encrypt_key'],
                metadata.get('reverse_map')
            )
            disasm = static.disassemble()
            static.print_disassembly()

    # Trace-based analysis
    if args.trace:
        with open(args.trace, 'r') as f:
            trace = json.load(f)

        if args.method in ('trace', 'all'):
            print(f"\n{'─'*60}")
            print("[策略 1] 基于 Trace 的模式匹配去虚拟化")
            print(f"{'─'*60}")

            td = TraceDevirtualizer()
            instructions = td.devirtualize(trace)

            print("\n还原的指令序列:")
            for i, inst in enumerate(instructions):
                print(f"  {i}: {inst}")

        if args.method in ('symbolic', 'all'):
            print(f"\n{'─'*60}")
            print("[策略 2] 基于符号执行的语义恢复")
            print(f"{'─'*60}")

            sd = SymbolicDevirtualizer()
            sym_regs = sd.devirtualize(trace)

            print("\n寄存器符号表达式:")
            for reg_idx, expr in sorted(sym_regs.items()):
                reduced = NandReducer.reduce(expr)
                original = repr(expr)
                simplified = repr(reduced)

                if original != simplified:
                    print(f"  R{reg_idx} = {simplified}")
                    print(f"       (原始: {original})")
                else:
                    print(f"  R{reg_idx} = {simplified}")


if __name__ == '__main__':
    main()
