# 对抗实战案例 (可运行)

每个案例都包含攻击方 (混淆/加密) 和防御方 (解混淆/解密) 的完整实现，可直接运行。

## 案例列表

### 01-mini-vm: VMP 风格虚拟化对抗

```
攻击方: vm_compiler.py    — 将表达式编译为加密 VM 字节码
攻击方: vm_interpreter.py — VM 解释器 (Dispatcher + Handler)
防御方: vm_devirtualizer.py — 三策略去虚拟化器
  ├── 策略 1: 基于 Trace 的模式匹配
  ├── 策略 2: 基于符号执行的语义恢复 (含 NAND 链化简)
  └── 策略 3: 静态字节码反汇编
```

```bash
# 编译
python3 vm_compiler.py hash --key 66 -o demo

# 执行 VM + 生成 trace
python3 vm_interpreter.py demo.vbc --regs 0x12345678 0xAABBCCDD 0 0 -v --dump-trace demo.trace.json

# 去虚拟化
python3 vm_devirtualizer.py --bytecode demo.vbc --trace demo.trace.json --method all
```

### 02-cff-attack-defense: 控制流平坦化对抗

```
攻击方: cff_obfuscator.py  — 将函数 CFG 变换为 switch-case dispatcher
防御方: cff_deflattener.py — 恢复原始控制流 + 差分验证
```

```bash
python3 cff_deflattener.py
```

### 03-mba-attack-defense: MBA 指令替换对抗

```
单文件: mba_battle.py
攻击方: 将 a+b 等运算替换为等价 MBA 表达式
防御方: 三种简化策略
  ├── 真值表穷举 (8-bit 完美匹配)
  ├── 随机采样验证
  └── 代数重写规则
```

```bash
python3 mba_battle.py
```

### 04-string-encrypt: 字符串加密对抗

```
单文件: string_battle.py
攻击方: 5 种加密方法 (XOR/Rolling/MultiKey/ADD/RC4)
防御方: 5 种解密策略
  ├── 暴力穷举 (单字节 XOR/ADD)
  ├── Rolling key seed 搜索
  ├── 频率分析
  ├── 已知明文攻击
  └── 自动检测
```

```bash
python3 string_battle.py
```

## 运行要求

- Python 3.7+
- 无第三方依赖 (纯标准库)
