# VMP 对抗实战案例

## 案例 1: VMP 2.x 基础去虚拟化

### 场景
目标: 一个使用 VMP 2.x Virtualization 模式保护的 crackme 程序，需要分析被保护的 license 校验函数。

### 分析流程

#### Step 1: 识别保护范围

```
1. 在 IDA 中加载目标二进制
2. 查找 .vmp0 section → 确认 VMP 2.x
3. 查找交叉引用: 从 license 相关字符串回溯
4. 定位 VM Entry: push 0xXXXXXXXX; pushad; pushfd 模式
```

#### Step 2: 定位 VM 组件

```python
# IDA Script: 定位关键组件
def locate_vm_components(entry_addr):
    # VMEntry 后的几条指令应该设置 VIP (ESI) 和 VSP (EBP)
    # 寻找 mov esi, [xxx] 和 mov ebp, esp 模式
    
    addr = entry_addr
    components = {}
    
    for i in range(50):  # 扫描前50条指令
        mnem = idc.print_insn_mnem(addr)
        op0 = idc.print_operand(addr, 0)
        op1 = idc.print_operand(addr, 1)
        
        if mnem == 'mov' and op0 == 'esi':
            components['vip_init'] = addr
        if mnem == 'mov' and op0 == 'ebp' and op1 == 'esp':
            components['vsp_init'] = addr
        if mnem == 'jmp' and is_in_vm_region(idc.get_operand_value(addr, 0)):
            components['dispatcher'] = idc.get_operand_value(addr, 0)
            break
        
        addr = idc.next_head(addr)
    
    return components
```

#### Step 3: Trace Handler 序列

```python
# x64dbg 脚本: 记录 handler trace
import x64dbg

def trace_vm(dispatcher, handler_count_limit=10000):
    trace = []
    bp = x64dbg.set_breakpoint(dispatcher)
    
    count = 0
    while count < handler_count_limit:
        x64dbg.run()
        
        if x64dbg.get_eip() != dispatcher:
            break
        
        vip = x64dbg.get_reg('esi')
        opcode = x64dbg.read_byte(vip)
        vsp = x64dbg.get_reg('ebp')
        
        # 解密 opcode (需要先逆向解密逻辑)
        key = x64dbg.get_reg('bl')  # 常见: key 在 BL
        real_opcode = opcode ^ key
        
        trace.append({
            'index': count,
            'vip': vip,
            'raw_opcode': opcode,
            'opcode': real_opcode,
            'vsp': vsp,
            'stack': [x64dbg.read_dword(vsp + i*4) for i in range(4)],
        })
        
        count += 1
    
    return trace
```

#### Step 4: 分析结果

```
Trace 片段 (简化):

#0  VIP=4050A0  OP=vPushImm32(0x1234)      VSP=7FFD0  Stack=[...]
#1  VIP=4050A5  OP=vPushReg(vR3)            VSP=7FFCC  Stack=[0x1234, ...]
#2  VIP=4050A7  OP=vAdd                     VSP=7FFD0  Stack=[input+0x1234, ...]
#3  VIP=4050A8  OP=vPushImm32(0x5678)      VSP=7FFCC  Stack=[input+0x1234, ...]
#4  VIP=4050AD  OP=vNand                    VSP=7FFD0  Stack=[~((input+0x1234)&0x5678), ...]
#5  VIP=4050AE  OP=vPopReg(vR3)             VSP=7FFD4  Stack=[...]

→ 还原: vR3 = ~((input + 0x1234) & 0x5678) = NAND(input+0x1234, 0x5678)
→ 等价: NOT (input + 0x1234) OR NOT 0x5678
```

### 最终还原

```c
// 原始 license 校验逻辑 (去虚拟化后还原)
bool check_license(const char* serial) {
    uint32_t hash = 0;
    for (int i = 0; serial[i]; i++) {
        hash = hash * 31 + serial[i];
    }
    hash ^= 0xDEADBEEF;
    hash = (hash >> 16) | (hash << 16);
    return hash == 0x12345678;
}
```

## 案例 2: VMP 3.x 反调试绕过

### 场景
目标程序使用 VMP 3.x Ultra 模式保护，内含强力反调试。需要先绕过反调试才能进行进一步分析。

### 反调试绕过方案

#### 方案 A: ScyllaHide 配置

```
ScyllaHide 推荐配置:
☑ PEB.BeingDebugged
☑ PEB.NtGlobalFlag
☑ PEB.HeapFlags
☑ NtSetInformationThread (HideFromDebugger)
☑ NtQueryInformationProcess (DebugPort)
☑ NtQueryInformationProcess (DebugObjectHandle)
☑ NtQueryInformationProcess (DebugFlags)
☑ NtQuerySystemInformation (SystemKernelDebuggerInformation)
☑ NtClose (InvalidHandle)
☑ Remove Debug Privileges
☑ OutputDebugString
☑ BlockInput
☑ GetTickCount / QueryPerformanceCounter (时间保护)
☑ NtSetDebugFilterState
```

#### 方案 B: 内核级绕过

```c
// TitanHide 驱动 - 核心思路
NTSTATUS HookedNtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS InfoClass,
    PVOID Buffer,
    ULONG Length,
    PULONG ReturnLength)
{
    NTSTATUS status = OriginalNtQueryInformationProcess(
        ProcessHandle, InfoClass, Buffer, Length, ReturnLength);
    
    if (NT_SUCCESS(status) && IsProtectedProcess(ProcessHandle)) {
        switch (InfoClass) {
            case ProcessDebugPort:          // 7
                *(PULONG_PTR)Buffer = 0;
                break;
            case ProcessDebugFlags:         // 0x1F
                *(PULONG)Buffer = PROCESS_DEBUG_INHERIT;
                break;
            case ProcessDebugObjectHandle:  // 0x1E
                status = STATUS_PORT_NOT_SET;
                break;
        }
    }
    
    return status;
}
```

#### 方案 C: Hypervisor 级 (最隐蔽)

```
使用 hypervisor (如 DdiMon / HyperDbg) 实现:
1. 在 VMX root mode 下执行调试操作
2. 对 Guest OS 完全透明
3. 拦截 CPUID/RDTSC 等指令
4. 隐藏调试寄存器 (DR0-DR7)
5. 不需要修改任何 OS 数据结构
```

### VMP 3.x CRC 校验绕过

```python
# Frida 脚本: 绕过 VMP 代码完整性校验
import frida

script_content = """
// Hook VirtualProtect 捕获 CRC 校验区域
Interceptor.attach(Module.findExportByName('kernel32.dll', 'VirtualProtect'), {
    onEnter: function(args) {
        this.addr = args[0];
        this.size = args[1].toInt32();
        this.prot = args[2].toInt32();
    },
    onLeave: function(retval) {
        if (this.prot === 0x40) { // PAGE_EXECUTE_READWRITE
            console.log(`VirtualProtect: ${this.addr} size=${this.size} → RWX`);
            // 可能是 CRC 校验前的页面属性修改
        }
    }
});

// 方法: Hook CRC 计算结果，强制返回预期值
// 需要先定位 CRC 校验函数的位置
var crcCheckAddr = ptr('0xXXXXXX');  // 替换为实际地址
Interceptor.attach(crcCheckAddr, {
    onLeave: function(retval) {
        // 强制 CRC 校验通过
        retval.replace(ptr(0));  // 或替换为预期的 CRC 值
    }
});
"""
```

## 案例 3: VMP 3.x 嵌套 VM 分析

### 场景
目标函数被 VMP 3.x 多层嵌套虚拟化保护。

### 分析策略

```
策略: 由外向内逐层分析

Layer 0 (原始代码):
  → VMEntry_L1 → Layer 1 VM
      → 分析 L1 的 handler 集合
      → 在 L1 bytecode 中发现 VMEntry_L2
      → VMEntry_L2 → Layer 2 VM
          → 分析 L2 的 handler 集合 (可能与 L1 不同)
          → 核心逻辑在 L2 中
          → VMExit_L2
      → 继续 L1 执行
      → VMExit_L1
  → 返回原始代码
```

### 自动化多层分析

```python
class NestedVMAnalyzer:
    def __init__(self):
        self.layers = []
        self.current_layer = 0
    
    def analyze(self, entry_point):
        """递归分析嵌套 VM"""
        layer = VMLayer(self.current_layer, entry_point)
        self.layers.append(layer)
        
        # 分析当前层
        layer.locate_components()
        layer.identify_handlers()
        trace = layer.trace_execution()
        
        # 在 trace 中寻找嵌套 VMEntry
        for i, entry in enumerate(trace):
            if self.is_nested_vm_entry(entry):
                self.current_layer += 1
                nested_result = self.analyze(entry.target)
                # 将嵌套结果插入当前层 trace
                trace[i] = nested_result
                self.current_layer -= 1
        
        # 去虚拟化当前层
        return self.devirtualize(trace)
    
    def is_nested_vm_entry(self, trace_entry):
        """检测是否为嵌套 VM 入口"""
        # 特征: handler 执行了另一个 push+pushad 序列
        # 或者跳转到了另一个 dispatcher
        return (trace_entry.handler_type == 'vCall' and 
                self.looks_like_vm_entry(trace_entry.target))
```

## 案例 4: Android SO 的 VMP 保护分析

### 场景
某 Android 游戏的 native SO 库使用 VMP 保护关键算法。

### 分析流程

```
1. 提取 APK 中的 .so 文件
2. 使用 IDA/Ghidra 加载 (ARM/ARM64)
3. 定位 JNI_OnLoad 和关键 JNI 函数
4. 识别 ARM 版 VMP 的 VM 组件
5. 使用 Frida 在设备上进行动态 trace
```

### ARM VMP 特征

```
ARM 版 VMP 与 x86 版的差异:
- 寄存器约定不同: R0-R15 vs EAX-EDI
- VIP 通常使用 R4/R5
- VSP 通常使用 R6/R7
- Dispatcher 使用 BX/BLX 而非 JMP
- Handler table 可能使用 TBB/TBH 指令
- Thumb/ARM 模式切换增加复杂性
```

### Frida on Android

```javascript
// Frida: Hook Android SO 中的 VMP
Java.perform(function() {
    var targetLib = 'libtarget.so';
    var base = Module.findBaseAddress(targetLib);
    
    if (!base) {
        console.log('Library not loaded yet, waiting...');
        var listener = Interceptor.attach(
            Module.findExportByName(null, 'dlopen'), {
            onLeave: function(retval) {
                if (Module.findBaseAddress(targetLib)) {
                    base = Module.findBaseAddress(targetLib);
                    console.log('Library loaded at: ' + base);
                    startAnalysis(base);
                    listener.detach();
                }
            }
        });
    } else {
        startAnalysis(base);
    }
});

function startAnalysis(base) {
    // VMP Dispatcher 的偏移 (通过静态分析确定)
    var dispatcherOffset = 0x1234;
    var dispatcher = base.add(dispatcherOffset);
    
    Interceptor.attach(dispatcher, {
        onEnter: function(args) {
            var vip = this.context.r4;  // ARM 的 VIP
            var vsp = this.context.r6;  // ARM 的 VSP
            var opcode = Memory.readU8(vip);
            
            console.log(JSON.stringify({
                vip: vip.toString(),
                opcode: '0x' + opcode.toString(16),
                vsp: vsp.toString(),
                r0: this.context.r0.toString(),
            }));
        }
    });
}
```

## 案例 5: VMP 保护的恶意软件分析

### 场景
恶意软件使用 VMP 保护其核心 C2 通信逻辑。需要提取 C2 地址和通信协议。

### 分析策略

```
恶意软件分析不同于常规逆向:
- 不需要完整去虚拟化
- 目标是提取 IOC (Indicators of Compromise)
- 关注网络通信、文件操作、注册表操作等外部行为
```

### 行为分析优先

```python
# 方法: Hook 系统 API，不需要理解 VM 内部
import frida

hooks = """
// Hook 网络相关 API
var ws2_32 = Module.findBaseAddress('ws2_32.dll');
Interceptor.attach(Module.findExportByName('ws2_32.dll', 'connect'), {
    onEnter: function(args) {
        var sockaddr = args[1];
        var family = Memory.readU16(sockaddr);
        if (family === 2) { // AF_INET
            var port = Memory.readU16(sockaddr.add(2));
            port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
            var ip = Memory.readU8(sockaddr.add(4)) + '.' +
                     Memory.readU8(sockaddr.add(5)) + '.' +
                     Memory.readU8(sockaddr.add(6)) + '.' +
                     Memory.readU8(sockaddr.add(7));
            console.log('[C2] connect → ' + ip + ':' + port);
        }
    }
});

// Hook DNS 解析
Interceptor.attach(Module.findExportByName('ws2_32.dll', 'getaddrinfo'), {
    onEnter: function(args) {
        var hostname = Memory.readUtf8String(args[0]);
        console.log('[DNS] Resolving: ' + hostname);
    }
});

// Hook 加密 API (可能用于 C2 通信加密)
Interceptor.attach(Module.findExportByName('advapi32.dll', 'CryptEncrypt'), {
    onEnter: function(args) {
        var dataLen = Memory.readU32(args[4]);
        var data = Memory.readByteArray(args[3], Math.min(dataLen, 256));
        console.log('[CRYPT] Encrypting ' + dataLen + ' bytes');
        console.log(hexdump(data));
    }
});
""";
```

### 内存字符串提取

```python
# 扫描 VMP 解密后的内存，提取 C2 相关字符串
def scan_memory_for_ioc(pid):
    """扫描进程内存中的 IOC"""
    import frida
    
    session = frida.attach(pid)
    script = session.create_script("""
    var ranges = Process.enumerateRanges('r--');
    var results = [];
    
    // URL 模式
    var urlPattern = /https?:\\/\\/[\\w\\-.]+(:\\d+)?[\\/\\w\\-.?&=%]*/g;
    // IP 模式
    var ipPattern = /\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(:\\d+)?/g;
    
    ranges.forEach(function(range) {
        try {
            var data = Memory.readUtf8String(range.base, Math.min(range.size, 0x100000));
            
            var urls = data.match(urlPattern);
            if (urls) results = results.concat(urls);
            
            var ips = data.match(ipPattern);
            if (ips) results = results.concat(ips);
        } catch(e) {}
    });
    
    send({type: 'ioc', data: [...new Set(results)]});
    """)
    
    results = []
    script.on('message', lambda msg, data: results.extend(msg['payload']['data']))
    script.load()
    
    return results
```
