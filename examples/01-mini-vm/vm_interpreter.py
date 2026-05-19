#!/usr/bin/env python3
"""
[攻击方] Mini-VMP 解释器
执行编译器产出的加密字节码，模拟 VMProtect 的 VM Dispatcher + Handler 执行。

架构:
  VMEntry → Dispatcher (fetch-decode-dispatch loop) → Handlers → VMExit
"""

import struct
import json
import sys


class MiniVM:
    def __init__(self, bytecode, encrypt_key, opcode_reverse_map=None):
        self.bytecode = bytecode
        self.key = encrypt_key
        self.reverse_map = {}
        if opcode_reverse_map:
            self.reverse_map = {int(k): v for k, v in opcode_reverse_map.items()}

        self.regs = [0] * 4       # R0-R3
        self.stack = []
        self.vip = 0              # Virtual Instruction Pointer
        self.zero_flag = False
        self.halted = False
        self.trace = []           # 执行 trace (供去虚拟化器使用)

    def _decrypt_byte(self, offset):
        return self.bytecode[offset] ^ self.key

    def _decrypt_dword(self, offset):
        raw = bytes(b ^ self.key for b in self.bytecode[offset:offset+4])
        return struct.unpack('<I', raw)[0]

    def _fetch_opcode(self):
        raw = self._decrypt_byte(self.vip)
        opcode = self.reverse_map.get(raw, raw)
        self.vip += 1
        return opcode

    def _fetch_operand(self):
        val = self._decrypt_dword(self.vip)
        self.vip += 4
        return val

    def _record_trace(self, handler_name, details=None):
        entry = {
            'vip': self.vip,
            'handler': handler_name,
            'stack_before': list(self.stack),
            'regs': list(self.regs),
        }
        if details:
            entry.update(details)
        self.trace.append(entry)

    def _mask32(self, val):
        return val & 0xFFFFFFFF

    def _signed32(self, val):
        val = val & 0xFFFFFFFF
        if val >= 0x80000000:
            return val - 0x100000000
        return val

    def run(self, initial_regs=None, verbose=False):
        if initial_regs:
            for i, v in enumerate(initial_regs[:4]):
                self.regs[i] = v & 0xFFFFFFFF

        if verbose:
            print(f"[VM] Start | Regs: R0={self.regs[0]:#010x} R1={self.regs[1]:#010x} "
                  f"R2={self.regs[2]:#010x} R3={self.regs[3]:#010x}")

        step = 0
        while not self.halted and self.vip < len(self.bytecode):
            saved_vip = self.vip
            opcode = self._fetch_opcode()
            self._dispatch(opcode, verbose)
            step += 1

            if step > 100000:
                print("[VM] ERROR: Exceeded max steps, possible infinite loop")
                break

        if verbose:
            print(f"[VM] Halt | Regs: R0={self.regs[0]:#010x} R1={self.regs[1]:#010x} "
                  f"R2={self.regs[2]:#010x} R3={self.regs[3]:#010x}")
            print(f"[VM] Steps: {step}")

        return self.regs

    def _dispatch(self, opcode, verbose):
        # Handler 表 (模拟 VMProtect 的 handler table dispatch)
        handlers = {
            0x01: self._h_push_reg,
            0x02: self._h_push_imm,
            0x03: self._h_pop_reg,
            0x10: self._h_add,
            0x11: self._h_sub,
            0x12: self._h_mul,
            0x13: self._h_xor,
            0x14: self._h_and,
            0x15: self._h_or,
            0x16: self._h_not,
            0x17: self._h_nand,
            0x18: self._h_shl,
            0x19: self._h_shr,
            0x20: self._h_cmp,
            0x30: self._h_jmp,
            0x31: self._h_jz,
            0x32: self._h_jnz,
            0xFF: self._h_halt,
        }

        handler = handlers.get(opcode)
        if handler is None:
            raise RuntimeError(f"Unknown opcode 0x{opcode:02X} at VIP={self.vip-1:#x}")

        handler(verbose)

    def _h_push_reg(self, verbose):
        reg = self._fetch_operand()
        val = self.regs[reg]
        self.stack.append(val)
        self._record_trace('PUSH_REG', {'reg': reg, 'value': val})
        if verbose:
            print(f"  PUSH_REG R{reg} (={val:#010x})")

    def _h_push_imm(self, verbose):
        val = self._fetch_operand()
        self.stack.append(val)
        self._record_trace('PUSH_IMM', {'value': val})
        if verbose:
            print(f"  PUSH_IMM {val:#010x}")

    def _h_pop_reg(self, verbose):
        reg = self._fetch_operand()
        val = self.stack.pop()
        self.regs[reg] = val
        self._record_trace('POP_REG', {'reg': reg, 'value': val})
        if verbose:
            print(f"  POP_REG  R{reg} (={val:#010x})")

    def _h_add(self, verbose):
        b = self.stack.pop()
        a = self.stack.pop()
        result = self._mask32(a + b)
        self.zero_flag = (result == 0)
        self.stack.append(result)
        self._record_trace('ADD', {'a': a, 'b': b, 'result': result})
        if verbose:
            print(f"  ADD      {a:#010x} + {b:#010x} = {result:#010x}")

    def _h_sub(self, verbose):
        b = self.stack.pop()
        a = self.stack.pop()
        result = self._mask32(a - b)
        self.zero_flag = (result == 0)
        self.stack.append(result)
        self._record_trace('SUB', {'a': a, 'b': b, 'result': result})
        if verbose:
            print(f"  SUB      {a:#010x} - {b:#010x} = {result:#010x}")

    def _h_mul(self, verbose):
        b = self.stack.pop()
        a = self.stack.pop()
        result = self._mask32(a * b)
        self.zero_flag = (result == 0)
        self.stack.append(result)
        self._record_trace('MUL', {'a': a, 'b': b, 'result': result})
        if verbose:
            print(f"  MUL      {a:#010x} * {b:#010x} = {result:#010x}")

    def _h_xor(self, verbose):
        b = self.stack.pop()
        a = self.stack.pop()
        result = a ^ b
        self.zero_flag = (result == 0)
        self.stack.append(result)
        self._record_trace('XOR', {'a': a, 'b': b, 'result': result})
        if verbose:
            print(f"  XOR      {a:#010x} ^ {b:#010x} = {result:#010x}")

    def _h_and(self, verbose):
        b = self.stack.pop()
        a = self.stack.pop()
        result = a & b
        self.zero_flag = (result == 0)
        self.stack.append(result)
        self._record_trace('AND', {'a': a, 'b': b, 'result': result})
        if verbose:
            print(f"  AND      {a:#010x} & {b:#010x} = {result:#010x}")

    def _h_or(self, verbose):
        b = self.stack.pop()
        a = self.stack.pop()
        result = a | b
        self.zero_flag = (result == 0)
        self.stack.append(result)
        self._record_trace('OR', {' a': a, 'b': b, 'result': result})
        if verbose:
            print(f"  OR       {a:#010x} | {b:#010x} = {result:#010x}")

    def _h_not(self, verbose):
        a = self.stack.pop()
        result = self._mask32(~a)
        self.stack.append(result)
        self._record_trace('NOT', {'a': a, 'result': result})
        if verbose:
            print(f"  NOT      ~{a:#010x} = {result:#010x}")

    def _h_nand(self, verbose):
        b = self.stack.pop()
        a = self.stack.pop()
        result = self._mask32(~(a & b))
        self.zero_flag = (result == 0)
        self.stack.append(result)
        self._record_trace('NAND', {'a': a, 'b': b, 'result': result})
        if verbose:
            print(f"  NAND     ~({a:#010x} & {b:#010x}) = {result:#010x}")

    def _h_shl(self, verbose):
        b = self.stack.pop()
        a = self.stack.pop()
        result = self._mask32(a << (b & 0x1F))
        self.stack.append(result)
        self._record_trace('SHL', {'a': a, 'b': b, 'result': result})
        if verbose:
            print(f"  SHL      {a:#010x} << {b} = {result:#010x}")

    def _h_shr(self, verbose):
        b = self.stack.pop()
        a = self.stack.pop()
        result = self._mask32(a >> (b & 0x1F))
        self.stack.append(result)
        self._record_trace('SHR', {'a': a, 'b': b, 'result': result})
        if verbose:
            print(f"  SHR      {a:#010x} >> {b} = {result:#010x}")

    def _h_cmp(self, verbose):
        b = self.stack.pop()
        a = self.stack.pop()
        result = self._mask32(a - b)
        self.zero_flag = (result == 0)
        self.stack.append(a)  # CMP doesn't consume, pushes back
        self._record_trace('CMP', {'a': a, 'b': b, 'zero': self.zero_flag})
        if verbose:
            print(f"  CMP      {a:#010x} vs {b:#010x} → ZF={self.zero_flag}")

    def _h_jmp(self, verbose):
        target = self._fetch_operand()
        self._record_trace('JMP', {'target': target})
        if verbose:
            print(f"  JMP      → {target:#x}")
        self.vip = target

    def _h_jz(self, verbose):
        target = self._fetch_operand()
        taken = self.zero_flag
        self._record_trace('JZ', {'target': target, 'taken': taken})
        if verbose:
            print(f"  JZ       → {target:#x} ({'TAKEN' if taken else 'not taken'})")
        if taken:
            self.vip = target

    def _h_jnz(self, verbose):
        target = self._fetch_operand()
        taken = not self.zero_flag
        self._record_trace('JNZ', {'target': target, 'taken': taken})
        if verbose:
            print(f"  JNZ      → {target:#x} ({'TAKEN' if taken else 'not taken'})")
        if taken:
            self.vip = target

    def _h_halt(self, verbose):
        self.halted = True
        self._record_trace('HALT')
        if verbose:
            print(f"  HALT")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Mini-VMP Interpreter')
    parser.add_argument('bytecode', help='Bytecode file (.vbc)')
    parser.add_argument('--meta', help='Metadata file (.meta.json)')
    parser.add_argument('--regs', nargs='+', type=lambda x: int(x, 0), default=[0,0,0,0],
                       help='Initial register values (R0 R1 R2 R3)')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--dump-trace', help='Dump execution trace to JSON file')
    args = parser.parse_args()

    with open(args.bytecode, 'rb') as f:
        bytecode = f.read()

    meta_file = args.meta or args.bytecode.replace('.vbc', '.meta.json')
    with open(meta_file, 'r') as f:
        metadata = json.load(f)

    vm = MiniVM(
        bytecode=bytecode,
        encrypt_key=metadata['encrypt_key'],
        opcode_reverse_map=metadata.get('reverse_map')
    )

    result = vm.run(initial_regs=args.regs, verbose=args.verbose)

    print(f"\n[Result] R0={result[0]:#010x} R1={result[1]:#010x} "
          f"R2={result[2]:#010x} R3={result[3]:#010x}")

    if args.dump_trace:
        with open(args.dump_trace, 'w') as f:
            json.dump(vm.trace, f, indent=2)
        print(f"[+] Trace dumped to {args.dump_trace} ({len(vm.trace)} entries)")


if __name__ == '__main__':
    main()
