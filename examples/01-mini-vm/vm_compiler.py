#!/usr/bin/env python3
"""
[攻击方] Mini-VMP 编译器
将简单的算术/逻辑表达式编译为自定义 VM 字节码。
模拟 VMProtect 将 x86 指令翻译为虚拟指令的过程。

VM 架构:
- 基于栈的虚拟机 (Stack-based VM)
- 4 个虚拟寄存器: R0-R3
- 虚拟栈
- 指令集: PUSH_REG, PUSH_IMM, POP_REG, ADD, SUB, XOR, AND, OR, NOT, NAND,
           MUL, CMP, JMP, JZ, JNZ, LOAD, STORE, HALT
"""

import struct
import random
import json
import os

# VM 操作码定义
class Opcode:
    PUSH_REG  = 0x01
    PUSH_IMM  = 0x02
    POP_REG   = 0x03
    ADD       = 0x10
    SUB       = 0x11
    MUL       = 0x12
    XOR       = 0x13
    AND       = 0x14
    OR        = 0x15
    NOT       = 0x16
    NAND      = 0x17
    SHL       = 0x18
    SHR       = 0x19
    CMP       = 0x20
    JMP       = 0x30
    JZ        = 0x31
    JNZ       = 0x32
    LOAD      = 0x40
    STORE     = 0x41
    HALT      = 0xFF

    NAMES = {
        0x01: 'PUSH_REG', 0x02: 'PUSH_IMM', 0x03: 'POP_REG',
        0x10: 'ADD', 0x11: 'SUB', 0x12: 'MUL',
        0x13: 'XOR', 0x14: 'AND', 0x15: 'OR',
        0x16: 'NOT', 0x17: 'NAND',
        0x18: 'SHL', 0x19: 'SHR',
        0x20: 'CMP',
        0x30: 'JMP', 0x31: 'JZ', 0x32: 'JNZ',
        0x40: 'LOAD', 0x41: 'STORE',
        0xFF: 'HALT',
    }


class VMCompiler:
    def __init__(self, encrypt_key=None, shuffle_opcodes=False):
        self.bytecode = bytearray()
        self.encrypt_key = encrypt_key or random.randint(0x01, 0xFF)
        self.opcode_map = {}
        self.reverse_map = {}

        if shuffle_opcodes:
            self._shuffle_opcodes()
        else:
            for attr in dir(Opcode):
                val = getattr(Opcode, attr)
                if isinstance(val, int) and attr != 'NAMES' and not attr.startswith('_'):
                    self.opcode_map[val] = val
                    self.reverse_map[val] = val

    def _shuffle_opcodes(self):
        original_opcodes = []
        for attr in dir(Opcode):
            val = getattr(Opcode, attr)
            if isinstance(val, int) and attr != 'NAMES' and not attr.startswith('_'):
                original_opcodes.append(val)

        shuffled = list(range(0x01, 0x01 + len(original_opcodes)))
        random.shuffle(shuffled)

        for orig, shuf in zip(original_opcodes, shuffled):
            self.opcode_map[orig] = shuf
            self.reverse_map[shuf] = orig

    def _emit(self, opcode, *operands):
        mapped = self.opcode_map.get(opcode, opcode)
        encrypted = mapped ^ self.encrypt_key
        self.bytecode.append(encrypted)

        for op in operands:
            if isinstance(op, int):
                encoded = struct.pack('<I', op & 0xFFFFFFFF)
                for b in encoded:
                    self.bytecode.append(b ^ self.encrypt_key)

    def emit_push_reg(self, reg_idx):
        self._emit(Opcode.PUSH_REG, reg_idx)

    def emit_push_imm(self, value):
        self._emit(Opcode.PUSH_IMM, value)

    def emit_pop_reg(self, reg_idx):
        self._emit(Opcode.POP_REG, reg_idx)

    def emit_add(self):
        self._emit(Opcode.ADD)

    def emit_sub(self):
        self._emit(Opcode.SUB)

    def emit_mul(self):
        self._emit(Opcode.MUL)

    def emit_xor(self):
        self._emit(Opcode.XOR)

    def emit_and(self):
        self._emit(Opcode.AND)

    def emit_or(self):
        self._emit(Opcode.OR)

    def emit_not(self):
        self._emit(Opcode.NOT)

    def emit_nand(self):
        self._emit(Opcode.NAND)

    def emit_shl(self):
        self._emit(Opcode.SHL)

    def emit_shr(self):
        self._emit(Opcode.SHR)

    def emit_halt(self):
        self._emit(Opcode.HALT)

    def emit_jmp(self, target):
        self._emit(Opcode.JMP, target)

    def emit_jz(self, target):
        self._emit(Opcode.JZ, target)

    def emit_jnz(self, target):
        self._emit(Opcode.JNZ, target)

    def current_offset(self):
        return len(self.bytecode)

    def get_bytecode(self):
        return bytes(self.bytecode)

    def get_metadata(self):
        return {
            'encrypt_key': self.encrypt_key,
            'opcode_map': {str(k): v for k, v in self.opcode_map.items()},
            'reverse_map': {str(k): v for k, v in self.reverse_map.items()},
            'bytecode_len': len(self.bytecode),
        }


def compile_add(compiler):
    """编译: R0 = R0 + R1 (模拟 add eax, ecx)"""
    compiler.emit_push_reg(0)   # push R0
    compiler.emit_push_reg(1)   # push R1
    compiler.emit_add()         # add
    compiler.emit_pop_reg(0)    # pop → R0
    compiler.emit_halt()


def compile_xor_add(compiler):
    """编译: R0 = (R0 ^ R1) + R2 (复合运算)"""
    compiler.emit_push_reg(0)
    compiler.emit_push_reg(1)
    compiler.emit_xor()
    compiler.emit_push_reg(2)
    compiler.emit_add()
    compiler.emit_pop_reg(0)
    compiler.emit_halt()


def compile_nand_logic(compiler):
    """
    编译: R0 = R0 AND R1 (使用 NAND 实现)
    AND(a,b) = NAND(NAND(a,b), NAND(a,b))
    模拟 VMP 用 NAND 门实现所有逻辑运算
    """
    # NAND(R0, R1) → stack
    compiler.emit_push_reg(0)
    compiler.emit_push_reg(1)
    compiler.emit_nand()         # ~(R0 & R1) on stack

    # 复制栈顶: push same value again
    # 由于没有 DUP 指令，我们重新计算一次
    compiler.emit_push_reg(0)
    compiler.emit_push_reg(1)
    compiler.emit_nand()         # ~(R0 & R1) on stack again

    # NAND(~(R0&R1), ~(R0&R1)) = ~~(R0&R1) = R0 & R1
    compiler.emit_nand()
    compiler.emit_pop_reg(0)     # R0 = R0 & R1
    compiler.emit_halt()


def compile_hash_function(compiler):
    """
    编译一个简单的哈希函数:
    hash = ((R0 ^ 0xDEADBEEF) + R1) * 31
    result = hash ^ (hash >> 16)
    模拟真实 VMP 保护的 license 校验
    """
    # Step 1: R0 ^ 0xDEADBEEF
    compiler.emit_push_reg(0)
    compiler.emit_push_imm(0xDEADBEEF)
    compiler.emit_xor()

    # Step 2: + R1
    compiler.emit_push_reg(1)
    compiler.emit_add()

    # Step 3: * 31
    compiler.emit_push_imm(31)
    compiler.emit_mul()
    compiler.emit_pop_reg(2)     # R2 = hash

    # Step 4: hash >> 16
    compiler.emit_push_reg(2)
    compiler.emit_push_imm(16)
    compiler.emit_shr()

    # Step 5: hash ^ (hash >> 16)
    compiler.emit_push_reg(2)
    compiler.emit_xor()
    compiler.emit_pop_reg(0)     # R0 = final result

    compiler.emit_halt()


def compile_conditional(compiler):
    """
    编译条件分支:
    if R0 == 0:
        R0 = R1 + 100
    else:
        R0 = R1 * 2
    模拟 VMP 的 vJcc handler
    """
    compiler.emit_push_reg(0)
    compiler.emit_push_imm(0)
    compiler.emit_sub()          # R0 - 0, sets zero flag

    # JZ to else_offset (will be patched)
    jz_offset = compiler.current_offset()
    compiler.emit_jz(0)          # placeholder

    # else branch: R0 = R1 * 2
    compiler.emit_push_reg(1)
    compiler.emit_push_imm(2)
    compiler.emit_mul()
    compiler.emit_pop_reg(0)
    jmp_offset = compiler.current_offset()
    compiler.emit_jmp(0)         # placeholder → end

    # then branch: R0 = R1 + 100
    then_offset = compiler.current_offset()
    compiler.emit_push_reg(1)
    compiler.emit_push_imm(100)
    compiler.emit_add()
    compiler.emit_pop_reg(0)

    end_offset = compiler.current_offset()
    compiler.emit_halt()

    # Patch jump targets (encrypted, so we need to re-encrypt)
    key = compiler.encrypt_key
    # Patch JZ target
    target_bytes = struct.pack('<I', then_offset)
    for i, b in enumerate(target_bytes):
        compiler.bytecode[jz_offset + 1 + i] = b ^ key

    # Patch JMP target
    target_bytes = struct.pack('<I', end_offset)
    for i, b in enumerate(target_bytes):
        compiler.bytecode[jmp_offset + 1 + i] = b ^ key


PROGRAMS = {
    'add':         ('R0 = R0 + R1', compile_add),
    'xor_add':     ('R0 = (R0 ^ R1) + R2', compile_xor_add),
    'nand_and':    ('R0 = R0 AND R1 (via NAND gates)', compile_nand_logic),
    'hash':        ('hash = ((R0^0xDEADBEEF)+R1)*31; R0 = hash^(hash>>16)', compile_hash_function),
    'conditional': ('if R0==0: R0=R1+100 else: R0=R1*2', compile_conditional),
}


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Mini-VMP Compiler')
    parser.add_argument('program', choices=PROGRAMS.keys(), help='Program to compile')
    parser.add_argument('--shuffle', action='store_true', help='Shuffle opcode mapping')
    parser.add_argument('--key', type=int, default=None, help='Encryption key (0-255)')
    parser.add_argument('--output', '-o', default=None, help='Output bytecode file')
    args = parser.parse_args()

    desc, compile_func = PROGRAMS[args.program]
    print(f"[*] Compiling: {desc}")

    compiler = VMCompiler(encrypt_key=args.key, shuffle_opcodes=args.shuffle)
    compile_func(compiler)

    bytecode = compiler.get_bytecode()
    metadata = compiler.get_metadata()

    output_base = args.output or f"program_{args.program}"
    bc_file = output_base + '.vbc'
    meta_file = output_base + '.meta.json'

    with open(bc_file, 'wb') as f:
        f.write(bytecode)
    with open(meta_file, 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] Bytecode: {bc_file} ({len(bytecode)} bytes)")
    print(f"[+] Metadata: {meta_file}")
    print(f"[+] Encrypt key: 0x{compiler.encrypt_key:02X}")
    if args.shuffle:
        print(f"[+] Opcode mapping shuffled (see metadata)")

    # 打印加密后的字节码 hex dump
    print(f"\n[*] Encrypted bytecode hex dump:")
    for i in range(0, len(bytecode), 16):
        hex_part = ' '.join(f'{b:02X}' for b in bytecode[i:i+16])
        print(f"  {i:04X}: {hex_part}")


if __name__ == '__main__':
    main()
