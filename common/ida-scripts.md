# IDA Pro 脚本集合 (VMP/OLLVM 对抗)

## 通用工具函数

```python
import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs

def get_func_blocks(func_addr):
    """获取函数所有基本块"""
    func = idaapi.get_func(func_addr)
    return list(idaapi.FlowChart(func))

def get_block_instructions(block):
    """获取基本块中的所有指令"""
    insns = []
    addr = block.start_ea
    while addr < block.end_ea:
        insns.append(addr)
        addr = idc.next_head(addr, block.end_ea)
    return insns

def read_bytes(addr, size):
    """读取内存字节"""
    return ida_bytes.get_bytes(addr, size)

def patch_nop(addr, size):
    """用 NOP 填充指定区域"""
    for i in range(size):
        ida_bytes.patch_byte(addr + i, 0x90)  # x86 NOP

def patch_jmp(addr, target):
    """在 addr 处 patch 一个 jmp target"""
    import struct
    offset = target - addr - 5  # 5 = E9 + 4-byte offset
    patch_data = b'\xE9' + struct.pack('<i', offset)
    for i, byte in enumerate(patch_data):
        ida_bytes.patch_byte(addr + i, byte)
    # NOP 剩余空间
    original_insn_size = idc.get_item_size(addr)
    for i in range(5, original_insn_size):
        ida_bytes.patch_byte(addr + i, 0x90)

def add_comment(addr, text, repeatable=False):
    """添加注释"""
    if repeatable:
        idc.set_cmt(addr, text, 1)
    else:
        idc.set_cmt(addr, text, 0)
```

## VMP 分析脚本

### 1. VMP 入口点检测

```python
def find_vmp_entries():
    """查找所有 VMP VM Entry 点"""
    entries = []
    
    for seg_ea in idautils.Segments():
        seg_name = idc.get_segm_name(seg_ea)
        seg_end = idc.get_segm_end(seg_ea)
        
        if not ('.text' in seg_name or '.vmp' in seg_name):
            continue
        
        addr = seg_ea
        while addr < seg_end - 10:
            # 模式 1: push imm32; pushad (0x68 XX XX XX XX 0x60)
            if idc.get_wide_byte(addr) == 0x68:
                next_byte = idc.get_wide_byte(addr + 5)
                if next_byte == 0x60:  # pushad
                    imm = idc.get_wide_dword(addr + 1)
                    entries.append({
                        'addr': addr,
                        'bytecode_ref': imm,
                        'pattern': 'push_imm32_pushad'
                    })
            
            # 模式 2: push imm32; call (0x68 XX XX XX XX 0xE8)
            if idc.get_wide_byte(addr) == 0x68:
                next_byte = idc.get_wide_byte(addr + 5)
                if next_byte == 0xE8:  # call
                    imm = idc.get_wide_dword(addr + 1)
                    entries.append({
                        'addr': addr,
                        'bytecode_ref': imm,
                        'pattern': 'push_imm32_call'
                    })
            
            addr = idc.next_head(addr, seg_end)
    
    # 标记找到的入口
    for entry in entries:
        idc.set_name(entry['addr'], f"VMEntry_{entry['addr']:X}", idc.SN_FORCE)
        add_comment(entry['addr'], f"VMP Entry (bytecode @ {entry['bytecode_ref']:#X})")
    
    print(f"Found {len(entries)} VM entry points")
    return entries
```

### 2. Handler 表提取

```python
def extract_handler_table(dispatcher_addr, num_handlers=256):
    """从 dispatcher 提取 handler 跳转表"""
    handlers = {}
    
    # 方法 1: 直接跳转表
    # jmp dword ptr [eax*4 + TABLE_BASE]
    for addr in range(dispatcher_addr, dispatcher_addr + 0x100):
        mnem = idc.print_insn_mnem(addr)
        if mnem == 'jmp':
            op = idc.print_operand(addr, 0)
            # 解析表基址
            if '*4' in op or '*8' in op:
                # 提取表地址
                table_base = extract_table_base(addr)
                if table_base:
                    for i in range(num_handlers):
                        handler_addr = idc.get_wide_dword(table_base + i * 4)
                        if handler_addr != 0:
                            handlers[i] = handler_addr
                    break
    
    # 方法 2: 比较链 (cmp + je)
    if not handlers:
        addr = dispatcher_addr
        for _ in range(num_handlers * 3):  # 每个 handler 约3条指令
            mnem = idc.print_insn_mnem(addr)
            if mnem == 'cmp':
                opcode_val = idc.get_operand_value(addr, 1)
                next_addr = idc.next_head(addr)
                next_mnem = idc.print_insn_mnem(next_addr)
                if next_mnem in ('je', 'jz'):
                    target = idc.get_operand_value(next_addr, 0)
                    handlers[opcode_val] = target
            addr = idc.next_head(addr)
    
    # 标记 handlers
    for opcode, handler_addr in sorted(handlers.items()):
        name = f"VH_{opcode:02X}"
        idc.set_name(handler_addr, name, idc.SN_FORCE)
        print(f"Handler 0x{opcode:02X} → {handler_addr:#X}")
    
    return handlers
```

### 3. Handler 语义分类

```python
def classify_handler(handler_addr, max_insns=30):
    """根据指令模式分类 handler"""
    insns = []
    addr = handler_addr
    
    for _ in range(max_insns):
        mnem = idc.print_insn_mnem(addr)
        op0 = idc.print_operand(addr, 0)
        op1 = idc.print_operand(addr, 1)
        insns.append((mnem, op0, op1))
        
        if mnem in ('jmp', 'ret'):
            break
        addr = idc.next_head(addr)
    
    # 分类规则
    mnems = [i[0] for i in insns]
    
    # vAdd: 包含 add [ebp], reg 和 pushfd
    if any('add' == m for m in mnems) and 'pushfd' in mnems:
        return 'vAdd'
    
    # vNand: 包含 and + not 和 pushfd
    if 'and' in mnems and 'not' in mnems and 'pushfd' in mnems:
        return 'vNand'
    
    # vPush: 包含 sub ebp, 4 和 mov [ebp], reg
    if any(insn[0] == 'sub' and 'ebp' in insn[1] for insn in insns):
        if any(insn[0] == 'mov' and '[ebp' in insn[1] for insn in insns):
            return 'vPush'
    
    # vPop: 包含 add ebp, 4 和 mov reg, [ebp]
    if any(insn[0] == 'add' and 'ebp' in insn[1] for insn in insns):
        if any(insn[0] == 'mov' and '[ebp' in insn[2] for insn in insns):
            return 'vPop'
    
    # vLoad: mov reg, [reg] 模式
    for insn in insns:
        if insn[0] == 'mov' and insn[1] and insn[2]:
            if '[' in insn[2] and insn[2].count('[') == 1:
                if not 'ebp' in insn[2] and not 'edi' in insn[2]:
                    return 'vLoad'
    
    # vStore: mov [reg], reg 模式
    for insn in insns:
        if insn[0] == 'mov' and '[' in insn[1]:
            if not 'ebp' in insn[1] and not 'edi' in insn[1]:
                return 'vStore'
    
    return 'unknown'

def classify_all_handlers(handlers):
    """分类所有 handler"""
    classified = {}
    for opcode, addr in handlers.items():
        handler_type = classify_handler(addr)
        classified[opcode] = {
            'addr': addr,
            'type': handler_type
        }
        add_comment(addr, f"Handler type: {handler_type}")
    
    # 统计
    type_counts = {}
    for info in classified.values():
        t = info['type']
        type_counts[t] = type_counts.get(t, 0) + 1
    
    print("\nHandler classification:")
    for t, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"  {t}: {count}")
    
    return classified
```

## OLLVM 分析脚本

### 1. 控制流平坦化检测

```python
def detect_flattened_functions(min_blocks=10, min_in_degree=5):
    """检测所有被控制流平坦化的函数"""
    flattened = []
    
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func:
            continue
        
        blocks = list(idaapi.FlowChart(func))
        if len(blocks) < min_blocks:
            continue
        
        # 计算入度
        max_in_degree = 0
        dispatcher_block = None
        for block in blocks:
            in_degree = len(list(block.preds()))
            if in_degree > max_in_degree:
                max_in_degree = in_degree
                dispatcher_block = block
        
        if max_in_degree >= min_in_degree:
            func_name = idc.get_func_name(func_ea)
            flattened.append({
                'addr': func_ea,
                'name': func_name,
                'num_blocks': len(blocks),
                'dispatcher_addr': dispatcher_block.start_ea,
                'dispatcher_in_degree': max_in_degree,
            })
    
    print(f"\nDetected {len(flattened)} flattened functions:")
    for f in flattened:
        print(f"  {f['addr']:#X} {f['name']}: "
              f"{f['num_blocks']} blocks, "
              f"dispatcher @ {f['dispatcher_addr']:#X} "
              f"(in_degree={f['dispatcher_in_degree']})")
    
    return flattened
```

### 2. 不透明谓词检测

```python
def find_opaque_predicates(func_addr):
    """在函数中查找不透明谓词"""
    func = idaapi.get_func(func_addr)
    predicates = []
    
    for block in idaapi.FlowChart(func):
        insns = get_block_instructions(block)
        if len(insns) < 3:
            continue
        
        # 检查最后一条是否为条件跳转
        last = insns[-1]
        mnem = idc.print_insn_mnem(last)
        
        if mnem not in ('jz', 'jnz', 'je', 'jne', 'jg', 'jl', 'jge', 'jle',
                        'ja', 'jb', 'jae', 'jbe', 'jo', 'jno', 'js', 'jns',
                        'BEQ', 'BNE', 'BGT', 'BLT', 'BGE', 'BLE'):
            continue
        
        # 回溯查找 test/cmp
        for i in range(len(insns) - 2, max(0, len(insns) - 6), -1):
            cmp_mnem = idc.print_insn_mnem(insns[i])
            if cmp_mnem in ('test', 'cmp', 'CMP', 'TST'):
                # 检查常见不透明谓词模式
                pattern = check_opaque_pattern(insns[max(0,i-5):i+1])
                if pattern:
                    predicates.append({
                        'branch_addr': last,
                        'compare_addr': insns[i],
                        'pattern': pattern,
                        'block': block.start_ea,
                    })
                break
    
    return predicates

def check_opaque_pattern(insn_addrs):
    """检查指令序列是否匹配已知不透明谓词模式"""
    mnems = [idc.print_insn_mnem(a) for a in insn_addrs]
    
    # 模式: lea + imul + and + test (x*(x+1) % 2)
    if ('lea' in mnems and 'imul' in mnems and 
        'and' in mnems and 'test' in mnems):
        return 'x*(x+1)_mod_2'
    
    # 模式: imul + test/cmp (x*x >= 0)
    if 'imul' in mnems:
        for addr in insn_addrs:
            if idc.print_insn_mnem(addr) == 'imul':
                op0 = idc.print_operand(addr, 0)
                op1 = idc.print_operand(addr, 1)
                if op0 == op1:  # x*x
                    return 'x_squared_nonneg'
    
    # 模式: or + test (x|1 != 0)
    if 'or' in mnems and 'test' in mnems:
        for addr in insn_addrs:
            if idc.print_insn_mnem(addr) == 'or':
                if idc.get_operand_value(addr, 1) == 1:
                    return 'x_or_1_nonzero'
    
    return None
```

### 3. 自动解平坦化

```python
def semi_auto_deflattening(func_addr):
    """半自动解平坦化脚本"""
    
    # Step 1: 定位组件
    blocks = get_func_blocks(func_addr)
    
    # 找 dispatcher
    dispatcher = max(blocks, key=lambda b: len(list(b.preds())))
    print(f"Dispatcher: {dispatcher.start_ea:#X}")
    
    # 找状态变量
    state_var = find_state_variable(dispatcher)
    print(f"State variable: {state_var}")
    
    # 找所有状态常量
    state_constants = {}
    for block in blocks:
        for addr in get_block_instructions(block):
            mnem = idc.print_insn_mnem(addr)
            if mnem in ('mov', 'MOV'):
                # 检查是否是对状态变量的赋值
                if is_state_var_write(addr, state_var):
                    val = idc.get_operand_value(addr, 1)
                    if val != 0 and val != 0xFFFFFFFF:
                        state_constants[val] = block.start_ea
                        print(f"  State 0x{val:08X} → Block {block.start_ea:#X}")
    
    # 建立映射
    print(f"\nFound {len(state_constants)} state constants")
    
    # Step 2: 找 case blocks 的状态转换
    transitions = {}
    for block in blocks:
        if block.start_ea == dispatcher.start_ea:
            continue
        
        # 找这个块设置的下一个状态值
        next_states = find_next_states(block, state_var)
        if next_states:
            transitions[block.start_ea] = next_states
            for ns in next_states:
                target = state_constants.get(ns['value'])
                print(f"  {block.start_ea:#X} → state 0x{ns['value']:08X} "
                      f"→ block {target:#X if target else '???'} "
                      f"({'cond' if ns.get('conditional') else 'uncond'})")
    
    return transitions, state_constants

def find_state_variable(dispatcher_block):
    """从 dispatcher 中找到状态变量"""
    for addr in get_block_instructions(dispatcher_block):
        mnem = idc.print_insn_mnem(addr)
        if mnem in ('cmp', 'CMP'):
            op0 = idc.print_operand(addr, 0)
            if '[' in op0:  # 内存操作数 → 栈上的状态变量
                return op0
            else:  # 寄存器 → 再找 load 这个寄存器的指令
                return op0
    return None
```

### 4. 批量 Patch 工具

```python
import struct

def batch_patch_transitions(transitions, state_to_block):
    """批量 patch: 将 jmp dispatcher 替换为直接跳转"""
    patched = 0
    
    for src_block, next_states in transitions.items():
        if len(next_states) == 1 and not next_states[0].get('conditional'):
            # 无条件转换
            target_state = next_states[0]['value']
            target_block = state_to_block.get(target_state)
            
            if target_block:
                # 找到 src_block 末尾的 jmp dispatcher
                jmp_addr = find_jmp_to_dispatcher(src_block)
                if jmp_addr:
                    patch_jmp(jmp_addr, target_block)
                    add_comment(jmp_addr, 
                               f"Patched: direct jmp to {target_block:#X}")
                    patched += 1
    
    print(f"\nPatched {patched} unconditional transitions")
    
    # 刷新 IDA 分析
    idaapi.plan_and_wait(idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea())

def find_jmp_to_dispatcher(block_addr):
    """找到基本块末尾跳转到 dispatcher 的指令"""
    func = idaapi.get_func(block_addr)
    for block in idaapi.FlowChart(func):
        if block.start_ea == block_addr:
            # 倒序扫描找 jmp
            addr = block.end_ea
            for _ in range(5):
                addr = idc.prev_head(addr, block.start_ea)
                if addr == idc.BADADDR:
                    break
                mnem = idc.print_insn_mnem(addr)
                if mnem in ('jmp', 'JMP', 'B'):
                    return addr
    return None
```

### 5. 一键分析脚本

```python
def one_click_analysis(func_addr):
    """一键分析混淆函数"""
    print("=" * 60)
    print(f"Analyzing function at {func_addr:#X}")
    print("=" * 60)
    
    func = idaapi.get_func(func_addr)
    blocks = list(idaapi.FlowChart(func))
    
    print(f"\n[INFO] Function size: {func.end_ea - func.start_ea} bytes")
    print(f"[INFO] Basic blocks: {len(blocks)}")
    
    # 1. 检测混淆类型
    print("\n--- Obfuscation Detection ---")
    
    max_in = max(len(list(b.preds())) for b in blocks)
    if max_in > 5:
        print(f"[DETECTED] Control Flow Flattening (dispatcher in_degree={max_in})")
    
    opaques = find_opaque_predicates(func_addr)
    if opaques:
        print(f"[DETECTED] Bogus Control Flow ({len(opaques)} opaque predicates)")
    
    # 2. 提取关键信息
    print("\n--- Key Components ---")
    
    # Dispatcher
    dispatcher = max(blocks, key=lambda b: len(list(b.preds())))
    print(f"Dispatcher: {dispatcher.start_ea:#X}")
    
    # State variable
    state_var = find_state_variable(dispatcher)
    print(f"State variable: {state_var}")
    
    # 3. 标记和注释
    print("\n--- Annotations ---")
    idc.set_color(dispatcher.start_ea, idc.CIC_ITEM, 0x0000FF)  # Red
    add_comment(dispatcher.start_ea, "OLLVM DISPATCHER")
    
    for pred in opaques:
        idc.set_color(pred['branch_addr'], idc.CIC_ITEM, 0x00FFFF)  # Yellow
        add_comment(pred['branch_addr'], 
                   f"OPAQUE PREDICATE: {pred['pattern']}")
    
    print(f"\nAnalysis complete. {len(opaques)} opaque predicates marked.")
    print("Use semi_auto_deflattening() for further analysis.")
```
