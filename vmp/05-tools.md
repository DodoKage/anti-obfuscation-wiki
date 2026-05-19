# VMP 对抗工具集

## 专用去虚拟化工具

### 1. VMProtect Devirtualizer (开源/学术)

#### NoVmp
- **仓库**: github.com/can1357/NoVmp
- **原理**: 基于 VTIL (Virtual-machine Translation Intermediate Language) 的去虚拟化框架
- **特点**:
  - 将 VMP handler 提升为 VTIL IR
  - 内置优化 pass（常量折叠、死代码消除、寄存器分配）
  - 支持 VMP 2.x 和部分 VMP 3.x
- **使用**:
```bash
# 基本用法
novmp.exe <input.vmp2> -o <output.exe>

# 指定 VM 入口
novmp.exe <input.vmp2> --entry 0x401000 -o <output.exe>
```

#### VTIL Project
- **仓库**: github.com/vtil-project
- **组件**:
  - **VTIL-Core**: IR 定义和基本优化
  - **VTIL-Architecture**: 架构抽象层
  - **VTIL-Optimizer**: 高级优化 pass
  - **VTIL-SymEx**: 符号执行引擎
- **特点**: 为虚拟机去虚拟化专门设计的 IR，比通用 IR 更适合

#### VMHunt
- **原理**: 基于 execution trace 的自动化 VM 分析
- **功能**:
  - 自动检测 VM-protected 区域
  - Handler 自动识别和分类
  - 生成简化的指令 trace

#### Saturn
- **原理**: 基于 Triton 的 VMP 分析框架
- **功能**: 
  - 符号执行驱动的 handler 语义提取
  - 自动化 bytecode 解密
  - 支持 VMP 3.x

### 2. VMUnprotect
- **仓库**: github.com/void-stack/VMUnprotect
- **类型**: .NET 平台的 VMP 去虚拟化工具
- **适用**: VMProtect 保护的 .NET 程序

## 通用逆向分析框架

### IDA Pro + 插件

#### IDA 核心使用

```python
# IDA Python: VMP 分析基础脚本

import idaapi
import idautils
import idc

def find_vmp_sections():
    """查找 VMP 相关的节"""
    for seg in idautils.Segments():
        name = idc.get_segm_name(seg)
        if '.vmp' in name.lower():
            print(f"VMP Section: {name} at {seg:#x}, size={idc.get_segm_end(seg)-seg:#x}")

def find_vm_entries():
    """查找可能的 VM 入口点"""
    entries = []
    for seg in idautils.Segments():
        addr = seg
        end = idc.get_segm_end(seg)
        while addr < end:
            # 查找 push imm32; pushad 模式
            if idc.get_wide_byte(addr) == 0x68:  # push imm32
                next_addr = addr + 5
                if idc.get_wide_byte(next_addr) == 0x60:  # pushad
                    entries.append(addr)
            addr = idc.next_head(addr, end)
    return entries

def trace_dispatcher(dispatcher_addr):
    """分析 dispatcher 的跳转表"""
    handlers = {}
    for xref in idautils.CodeRefsFrom(dispatcher_addr, 0):
        # 分析每个 handler
        handler_info = analyze_handler_brief(xref)
        handlers[xref] = handler_info
    return handlers
```

#### Hex-Rays Decompiler 辅助

```python
# 使用 Hex-Rays microcode 分析 handler
import ida_hexrays

def decompile_handler(handler_addr):
    """反编译单个 handler"""
    func = idaapi.get_func(handler_addr)
    if func:
        cfunc = idaapi.decompile(func)
        if cfunc:
            return str(cfunc)
    return None

class VMHandlerVisitor(ida_hexrays.ctree_visitor_t):
    """遍历 handler 的 AST"""
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.operations = []
    
    def visit_expr(self, expr):
        if expr.op == ida_hexrays.cot_add:
            self.operations.append(('add', expr))
        elif expr.op == ida_hexrays.cot_sub:
            self.operations.append(('sub', expr))
        return 0
```

### Ghidra + 脚本

```java
// Ghidra Script: VMP Handler 分析
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class VMPHandlerAnalyzer extends GhidraScript {
    @Override
    protected void run() throws Exception {
        // 查找所有 handler
        Address dispatcherAddr = askAddress("Dispatcher Address", "Enter dispatcher address:");
        
        // 获取跳转表引用
        Reference[] refs = getReferencesFrom(dispatcherAddr);
        
        for (Reference ref : refs) {
            Address handlerAddr = ref.getToAddress();
            analyzeHandler(handlerAddr);
        }
    }
    
    private void analyzeHandler(Address addr) {
        InstructionIterator iter = currentProgram.getListing().getInstructions(addr, true);
        StringBuilder sb = new StringBuilder();
        
        int count = 0;
        while (iter.hasNext() && count < 30) {
            Instruction inst = iter.next();
            sb.append(inst.toString()).append("\n");
            
            // 检测返回到 dispatcher 的跳转
            if (inst.getMnemonicString().startsWith("JMP")) {
                break;
            }
            count++;
        }
        
        println("Handler at " + addr + ":\n" + sb.toString());
    }
}
```

### Binary Ninja

```python
# Binary Ninja: VMP 分析
from binaryninja import *

def analyze_vmp(bv):
    # 使用 MLIL (Medium Level IL) 分析 handler
    for func in bv.functions:
        if is_vmp_handler(func):
            mlil = func.medium_level_il
            for block in mlil:
                for inst in block:
                    # MLIL 提供了更高级的语义视图
                    if isinstance(inst, MediumLevelILStore):
                        print(f"Store: {inst.dest} = {inst.src}")
                    elif isinstance(inst, MediumLevelILLoad):
                        print(f"Load: {inst}")
```

## 动态分析工具

### x64dbg + 插件

#### ScyllaHide (反反调试)
```
插件功能:
- 隐藏调试器存在
- 绕过 PEB 检测
- Hook NtQueryInformationProcess
- 处理 timing 检测
- 隐藏硬件/软件断点
```

#### TitanHide (内核级)
```
驱动级反反调试:
- SSDT Hook
- 内核调试对象隐藏
- 进程信息伪造
```

### Frida (动态插桩)

```javascript
// Frida: Hook VMP Dispatcher
'use strict';

const DISPATCHER_ADDR = ptr('0x401000');
const HANDLER_TABLE = ptr('0x405000');

Interceptor.attach(DISPATCHER_ADDR, {
    onEnter: function(args) {
        // 读取当前 opcode
        const vip = this.context.esi;
        const opcode = Memory.readU8(vip);
        
        // 读取虚拟栈顶
        const vsp = this.context.ebp;
        const stackTop = Memory.readU32(vsp);
        
        // 读取 handler 地址
        const handlerAddr = Memory.readPointer(HANDLER_TABLE.add(opcode * 4));
        
        console.log(`VIP=${vip} OP=0x${opcode.toString(16)} ` +
                    `Handler=${handlerAddr} VSP=${vsp} Top=0x${stackTop.toString(16)}`);
    }
});
```

```javascript
// Frida: 绕过 VMP 反调试
Interceptor.attach(Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess'), {
    onEnter: function(args) {
        this.infoClass = args[1].toInt32();
        this.buffer = args[2];
    },
    onLeave: function(retval) {
        // ProcessDebugPort = 7
        if (this.infoClass === 7) {
            Memory.writeU32(this.buffer, 0);
        }
        // ProcessDebugFlags = 0x1f
        if (this.infoClass === 0x1f) {
            Memory.writeU32(this.buffer, 1);
        }
        // ProcessDebugObjectHandle = 0x1e
        if (this.infoClass === 0x1e) {
            retval.replace(0xC0000353); // STATUS_PORT_NOT_SET
        }
    }
});
```

### Intel Pin (动态二进制插桩)

```cpp
// Pin Tool: VMP Instruction Trace
#include "pin.H"
#include <fstream>

static std::ofstream trace_file;
static ADDRINT dispatcher_addr = 0;
static ADDRINT vm_start = 0;
static ADDRINT vm_end = 0;

VOID RecordHandler(ADDRINT ip, ADDRINT vip, ADDRINT vsp) {
    if (ip >= vm_start && ip <= vm_end) {
        trace_file << std::hex 
                   << "IP=" << ip 
                   << " VIP=" << vip 
                   << " VSP=" << vsp << std::endl;
    }
}

VOID Instruction(INS ins, VOID *v) {
    ADDRINT addr = INS_Address(ins);
    if (addr >= vm_start && addr <= vm_end) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordHandler,
                      IARG_INST_PTR,
                      IARG_REG_VALUE, REG_ESI,  // VIP
                      IARG_REG_VALUE, REG_EBP,  // VSP
                      IARG_END);
    }
}
```

### Unicorn Engine (模拟执行)

```python
from unicorn import *
from unicorn.x86_const import *
import struct

class VMPEmulator:
    def __init__(self, code, base_addr=0x400000):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.base = base_addr
        self.trace = []
        
        # 映射内存
        self.uc.mem_map(base_addr, 0x100000)  # 代码段
        self.uc.mem_map(0x7FF00000, 0x100000)  # 栈
        
        # 写入代码
        self.uc.mem_write(base_addr, code)
        
        # 初始化栈
        self.uc.reg_write(UC_X86_REG_ESP, 0x7FF80000)
        
        # 设置 hook
        self.uc.hook_add(UC_HOOK_CODE, self._code_hook)
    
    def _code_hook(self, uc, address, size, user_data):
        vip = uc.reg_read(UC_X86_REG_ESI)
        vsp = uc.reg_read(UC_X86_REG_EBP)
        
        if address == self.dispatcher_addr:
            opcode = struct.unpack('B', uc.mem_read(vip, 1))[0]
            self.trace.append({
                'addr': address,
                'vip': vip,
                'vsp': vsp,
                'opcode': opcode,
            })
    
    def emulate(self, start, end):
        self.uc.emu_start(start, end, timeout=30*1000000)
        return self.trace
```

## 符号执行框架

### Triton

```python
from triton import *

class VMPTritonAnalyzer:
    def __init__(self):
        self.ctx = TritonContext(ARCH.X86)
        self.ctx.setMode(MODE.ALIGNED_MEMORY, True)
        self.ctx.setMode(MODE.AST_OPTIMIZATIONS, True)
    
    def analyze_handler(self, handler_bytes, handler_addr):
        """分析单个 handler 的符号语义"""
        # 符号化输入
        self.ctx.symbolizeRegister(self.ctx.registers.eax, "input_eax")
        self.ctx.symbolizeRegister(self.ctx.registers.ebp, "VSP")
        self.ctx.symbolizeRegister(self.ctx.registers.esi, "VIP")
        
        # 模拟执行
        offset = 0
        while offset < len(handler_bytes):
            inst = Instruction(handler_addr + offset, handler_bytes[offset:offset+16])
            self.ctx.processing(inst)
            
            if inst.getType() == OPCODE.X86.JMP:
                break
            offset += inst.getSize()
        
        # 提取语义
        output_eax = self.ctx.getSymbolicRegister(self.ctx.registers.eax)
        output_ebp = self.ctx.getSymbolicRegister(self.ctx.registers.ebp)
        
        if output_eax:
            simplified = self.ctx.simplify(output_eax.getAst(), True)
            print(f"EAX = {simplified}")
        
        return self.get_effects()
```

### angr

```python
import angr
import claripy

class VMPAngrAnalyzer:
    def __init__(self, binary_path):
        self.proj = angr.Project(binary_path, auto_load_libs=False)
    
    def symbolic_trace(self, vm_entry, vm_exit):
        """符号执行整个 VM 区域"""
        state = self.proj.factory.blank_state(
            addr=vm_entry,
            add_options={angr.options.LAZY_SOLVES}
        )
        
        # 符号化关键寄存器
        for reg in ['eax', 'ecx', 'edx', 'ebx']:
            sym_var = claripy.BVS(f"input_{reg}", 32)
            setattr(state.regs, reg, sym_var)
        
        # 设置 VM 区域约束
        simgr = self.proj.factory.simulation_manager(state)
        
        # Step until VMExit
        while simgr.active:
            simgr.step()
            
            # 检查是否到达 VMExit
            for s in simgr.active:
                if s.addr == vm_exit:
                    return self.extract_semantics(s)
            
            # 路径裁剪
            if len(simgr.active) > 100:
                simgr.move('active', 'pruned', 
                          filter_func=lambda s: s.history.depth > 5000)
        
        return None
```

## 实用脚本集合

### 快速定位 VMP 版本

```python
# 检测 VMP 版本的简单方法
def detect_vmp_version(pe_path):
    import pefile
    pe = pefile.PE(pe_path)
    
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        if '.vmp0' in name:
            return 'VMP 2.x'
        if '.vmp1' in name:
            return 'VMP 3.x'
    
    # 检查导入表
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode()
        if 'VMProtect' in dll_name:
            return 'VMP (version unknown)'
    
    return 'Not VMP or packed'
```

### 自动脱壳辅助

```python
# 使用 PE-sieve 检测解包后的代码
import subprocess

def dump_unpacked(pid):
    """使用 pe-sieve 转储已解包的内存"""
    result = subprocess.run(
        ['pe-sieve64.exe', '/pid', str(pid), '/imp', '2', '/dump', '1'],
        capture_output=True, text=True
    )
    return result.stdout
```
